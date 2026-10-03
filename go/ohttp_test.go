package nearai

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"golang.org/x/crypto/hkdf"
)

// Server framing is deliberately separate from production encoders/decoders.
func serverInt(n int) []byte {
	if n < 64 {
		return []byte{byte(n)}
	}
	if n < 16384 {
		return []byte{byte(n>>8) | 64, byte(n)}
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(n)|0x80000000)
	return b
}
func serverVector(b []byte) []byte { return append(serverInt(len(b)), b...) }
func serverReadInt(t *testing.T, r *bytes.Reader) int {
	t.Helper()
	first, e := r.ReadByte()
	if e != nil {
		t.Fatal(e)
	}
	size := 1 << (first >> 6)
	n := int(first & 63)
	for i := 1; i < size; i++ {
		b, e := r.ReadByte()
		if e != nil {
			t.Fatal(e)
		}
		n = n<<8 | int(b)
	}
	return n
}
func serverReadVector(t *testing.T, r *bytes.Reader) []byte {
	t.Helper()
	b := make([]byte, serverReadInt(t, r))
	if _, e := io.ReadFull(r, b); e != nil {
		t.Fatal(e)
	}
	return b
}
func TestOHTTPWireRoundtripAndFinalAuthentication(t *testing.T) {
	for _, framing := range []byte{1, 3} {
		for _, variant := range []string{"ok", "corrupt final", "omit final", "truncate", "wrong length", "bad padding"} {
			t.Run(itoa(int(framing))+variant, func(t *testing.T) {
				pub, priv, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
				if e != nil {
					t.Fatal(e)
				}
				pubBytes, _ := pub.MarshalBinary()
				config := append([]byte{1, 0, 32}, pubBytes...)
				config = append(config, 0, 4, 0, 1, 0, 1)
				reply := []byte("data: {\"id\":\"test\",\"choices\":[]}\n\ndata: [DONE]\n\n")
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					wire, _ := io.ReadAll(r.Body)
					if r.URL.Path != "/ohttp" || r.Header.Get("Authorization") != "Bearer relay" || r.Header.Get("X-Client-Pub-Key") != "" {
						t.Error("outer headers or path")
					}
					if bytes.Contains(wire, []byte("sensitive")) {
						t.Error("plaintext leaked")
					}
					if len(wire) < 39 {
						t.Error("short request")
						return
					}
					header, enc := wire[:7], wire[7:39]
					suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
					receiver, e := suite.NewReceiver(priv, append([]byte("message/bhttp chunked request\x00"), header...))
					if e != nil {
						t.Error(e)
						return
					}
					opener, e := receiver.Setup(enc)
					if e != nil {
						t.Error(e)
						return
					}
					reader := bytes.NewReader(wire[39:])
					var plain []byte
					for {
						size := serverReadInt(t, reader)
						aad := []byte(nil)
						if size == 0 {
							size = reader.Len()
							aad = []byte("final")
						}
						chunk := make([]byte, size)
						io.ReadFull(reader, chunk)
						p, e := opener.Open(chunk, aad)
						if e != nil {
							t.Error(e)
							return
						}
						plain = append(plain, p...)
						if aad != nil {
							break
						}
					}
					bhttp := bytes.NewReader(plain)
					if serverReadInt(t, bhttp) != 0 {
						t.Error("request framing")
					}
					for _, want := range []string{"POST", "http", r.Host, "/v1/chat/completions"} {
						if got := string(serverReadVector(t, bhttp)); got != want {
							t.Errorf("%q != %q", got, want)
						}
					}
					headers := bytes.NewReader(serverReadVector(t, bhttp))
					found := false
					for headers.Len() > 0 {
						name, value := string(serverReadVector(t, headers)), string(serverReadVector(t, headers))
						if name == "x-client-pub-key" && value == "private-header" {
							found = true
						}
					}
					if !found {
						t.Error("missing inner encryption header")
					}
					if !bytes.Equal(serverReadVector(t, bhttp), []byte("sensitive")) {
						t.Error("body mismatch")
					}
					responseNonce := make([]byte, 16)
					rand.Read(responseNonce)
					salt := append(append([]byte{}, enc...), responseNonce...)
					mac := hmac.New(sha256.New, salt)
					mac.Write(opener.Export([]byte("message/bhttp chunked response"), 16))
					prk := mac.Sum(nil)
					key := make([]byte, 16)
					nonce := make([]byte, 12)
					io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("key")), key)
					io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("nonce")), nonce)
					block, _ := aes.NewCipher(key)
					aead, _ := cipher.NewGCM(block)
					fields := append(serverVector([]byte("content-type")), serverVector([]byte("text/event-stream"))...)
					if variant == "wrong length" {
						fields = append(fields, serverVector([]byte("content-length"))...)
						fields = append(fields, serverVector([]byte("999"))...)
					}
					plaintext := append([]byte{framing}, serverInt(200)...)
					if framing == 1 {
						plaintext = append(plaintext, serverVector(fields)...)
					} else {
						plaintext = append(plaintext, fields...)
						plaintext = append(plaintext, 0)
					}
					plaintext = append(plaintext, serverVector(reply)...)
					if framing == 3 {
						plaintext = append(plaintext, 0)
					}
					plaintext = append(plaintext, 0)
					if variant == "bad padding" {
						plaintext = append(plaintext, 1)
					}
					first := aead.Seal(nil, nonce, plaintext, nil)
					response := append(responseNonce, serverInt(len(first))...)
					response = append(response, first...)
					if variant != "omit final" {
						nonce[11] ^= 1
						final := aead.Seal(nil, nonce, nil, []byte("final"))
						if variant == "corrupt final" {
							final[0] ^= 1
						}
						response = append(response, 0)
						response = append(response, final...)
					}
					if variant == "truncate" {
						response = response[:len(response)-1]
					}
					w.Header().Set("Content-Type", "message/ohttp-chunked-res")
					w.Write(response)
				}))
				defer server.Close()
				transport, e := NewOHTTPTransport(config, server.URL, nil, []string{"X-Client-Pub-Key"})
				if e != nil {
					t.Fatal(e)
				}
				req, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader("sensitive"))
				req.Header.Set("Authorization", "Bearer relay")
				req.Header.Set("X-Client-Pub-Key", "private-header")
				response, e := transport.RoundTrip(req)
				if e != nil {
					if variant == "ok" {
						t.Fatal(e)
					}
					return
				}
				defer response.Body.Close()
				body, e := io.ReadAll(response.Body)
				if variant == "ok" {
					if e != nil || !bytes.Equal(body, reply) {
						t.Fatalf("%s %v", body, e)
					}
				} else if e == nil {
					t.Fatal("invalid encrypted response accepted")
				}
			})
		}
	}
}
func TestVarintBoundaries(t *testing.T) {
	for _, n := range []uint64{0, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, 1 << 40} {
		v, e := readVarint(bufio.NewReader(bytes.NewReader(varint(n))), false)
		if e != nil || v != n {
			t.Fatalf("%d %d %v", n, v, e)
		}
	}
}
