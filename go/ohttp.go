package nearai

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/hkdf"
)

const ohttpChunkSize = 16384

var ohttpSuite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
var requestLabel = []byte("message/bhttp chunked request")
var responseLabel = []byte("message/bhttp chunked response")

type ohttpTransport struct {
	header    []byte
	key       kem.PublicKey
	relay     *url.URL
	base      http.RoundTripper
	forwarded map[string]bool
}

// NewOHTTPTransport encapsulates same-origin requests using an authenticated
// key configuration. Authorization and explicitly forwarded headers remain
// visible to the relay. Body and encryption headers stay inside OHTTP.
func NewOHTTPTransport(config []byte, baseURL string, base http.RoundTripper, forwarded []string) (http.RoundTripper, error) {
	if len(config) < 41 || config[1] != 0 || config[2] != 32 {
		return nil, failure("ohttp.key_config_invalid", nil)
	}
	size := int(binary.BigEndian.Uint16(config[35:37]))
	if size == 0 || size%4 != 0 || len(config) != 37+size {
		return nil, failure("ohttp.key_config_invalid", nil)
	}
	supported := false
	for i := 37; i < len(config); i += 4 {
		if bytes.Equal(config[i:i+4], []byte{0, 1, 0, 1}) {
			supported = true
		}
	}
	if !supported {
		return nil, failure("ohttp.key_config_invalid", nil)
	}
	pub, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(config[3:35])
	if e != nil {
		return nil, failure("ohttp.key_config_invalid", e)
	}
	u, e := url.Parse(baseURL)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, failure("api.invalid_input", e)
	}
	u.Path = "/ohttp"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	if base == nil {
		base = http.DefaultTransport
	}
	names := map[string]bool{"authorization": true}
	for _, n := range forwarded {
		names[strings.ToLower(n)] = true
	}
	return &ohttpTransport{append([]byte{config[0]}, 0, 32, 0, 1, 0, 1), pub, u, base, names}, nil
}
func varint(v uint64) []byte {
	switch {
	case v < 1<<6:
		return []byte{byte(v)}
	case v < 1<<14:
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(v)|0x4000)
		return b
	case v < 1<<30:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v)|0x80000000)
		return b
	default:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v|0xc000000000000000)
		return b
	}
}
func vector(b []byte) []byte { return append(varint(uint64(len(b))), b...) }
func readVarint(r *bufio.Reader, eofZero bool) (uint64, error) {
	b, e := r.ReadByte()
	if e == io.EOF && eofZero {
		return 0, nil
	}
	if e != nil {
		return 0, e
	}
	size := 1 << (b >> 6)
	v := uint64(b & 63)
	for i := 1; i < size; i++ {
		b, e = r.ReadByte()
		if e != nil {
			return 0, io.ErrUnexpectedEOF
		}
		v = v<<8 | uint64(b)
	}
	return v, nil
}
func exact(r io.Reader, n uint64, limit uint64) ([]byte, error) {
	if n > limit {
		return nil, failure("ohttp.decryption_failed", nil)
	}
	b := make([]byte, int(n))
	_, e := io.ReadFull(r, b)
	return b, e
}
func hopHeaders(h http.Header) map[string]bool {
	skip := map[string]bool{}
	for _, s := range []string{"connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailer"} {
		skip[s] = true
	}
	for _, s := range strings.Split(h.Get("Connection"), ",") {
		skip[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return skip
}
func encodeBHTTPRequest(req *http.Request, body []byte) ([]byte, error) {
	fields := []byte{}
	skip := hopHeaders(req.Header)
	for k, values := range req.Header {
		if skip[strings.ToLower(k)] {
			continue
		}
		for _, v := range values {
			fields = append(fields, vector([]byte(strings.ToLower(k)))...)
			fields = append(fields, vector([]byte(v))...)
		}
	}
	authority := req.URL.Host
	if req.Host != "" {
		authority = req.Host
	}
	encoded := []byte{0}
	for _, v := range []string{req.Method, req.URL.Scheme, authority, req.URL.RequestURI()} {
		encoded = append(encoded, vector([]byte(v))...)
	}
	encoded = append(encoded, vector(fields)...)
	encoded = append(encoded, vector(body)...)
	encoded = append(encoded, 0)
	padding := (ohttpChunkSize - len(encoded)%ohttpChunkSize) % ohttpChunkSize
	encoded = append(encoded, make([]byte, padding)...)
	if len(encoded) > 1<<30 {
		return nil, failure("ohttp.encryption_failed", nil)
	}
	return encoded, nil
}
func (t *ohttpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != t.relay.Scheme || req.URL.Host != t.relay.Host {
		return nil, failure("api.invalid_input", nil)
	}
	var body []byte
	var e error
	if req.Body != nil {
		body, e = readBounded(req.Body, 64<<20)
		req.Body.Close()
		if e != nil {
			return nil, e
		}
	}
	plain, e := encodeBHTTPRequest(req, body)
	if e != nil {
		return nil, e
	}
	sender, e := ohttpSuite.NewSender(t.key, append(append(append([]byte{}, requestLabel...), 0), t.header...))
	if e != nil {
		return nil, e
	}
	enc, context, e := sender.Setup(rand.Reader)
	if e != nil {
		return nil, e
	}
	wire := append(append([]byte{}, t.header...), enc...)
	for off := 0; off < len(plain); off += ohttpChunkSize {
		end := min(off+ohttpChunkSize, len(plain))
		final := end == len(plain)
		var aad []byte
		if final {
			aad = []byte("final")
		}
		chunk, e := context.Seal(plain[off:end], aad)
		if e != nil {
			return nil, failure("ohttp.encryption_failed", e)
		}
		length := len(chunk)
		if final {
			length = 0
		}
		wire = append(wire, varint(uint64(length))...)
		wire = append(wire, chunk...)
	}
	outer, e := http.NewRequestWithContext(req.Context(), "POST", t.relay.String(), bytes.NewReader(wire))
	if e != nil {
		return nil, e
	}
	for name, values := range req.Header {
		n := strings.ToLower(name)
		if t.forwarded[n] && !strings.HasPrefix(n, "content-") && !hopHeaders(req.Header)[n] && n != "host" && n != "x-signing-algo" && n != "x-client-pub-key" && n != "x-model-pub-key" && n != "x-encryption-version" && n != "x-encrypt-all-fields" {
			outer.Header[name] = append([]string(nil), values...)
		}
	}
	outer.Header.Set("Content-Type", "message/ohttp-chunked-req")
	outer.Header.Set("Incremental", "?1")
	res, e := t.base.RoundTrip(outer)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*http.Response, error) {
		res.Body.Close()
		return nil, failure("ohttp.decryption_failed", e)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		res.Body.Close()
		return nil, &Error{Code: "api.http_status", Details: map[string]any{"status": res.StatusCode}, Retryable: res.StatusCode == 429 || res.StatusCode >= 500}
	}
	if strings.ToLower(strings.TrimSpace(strings.Split(res.Header.Get("Content-Type"), ";")[0])) != "message/ohttp-chunked-res" {
		return fail(fmt.Errorf("invalid content type"))
	}
	encrypted := bufio.NewReader(res.Body)
	responseNonce, e := exact(encrypted, 16, 16)
	if e != nil {
		return fail(e)
	}
	secret := context.Export(responseLabel, 16)
	prk := hkdf.Extract(sha256.New, secret, append(enc, responseNonce...))
	key := make([]byte, 16)
	n := make([]byte, 12)
	if _, e = io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("key")), key); e != nil {
		return fail(e)
	}
	if _, e = io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("nonce")), n); e != nil {
		return fail(e)
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return fail(e)
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return fail(e)
	}
	decrypted := bufio.NewReader(&ohttpDecryptReader{reader: encrypted, aead: aead, nonce: n})
	framing, e := readVarint(decrypted, false)
	if e != nil || (framing != 1 && framing != 3) {
		return fail(e)
	}
	known := framing == 1
	var status uint64
	var headers http.Header
	var expected int64
	for {
		status, e = readVarint(decrypted, false)
		if e != nil || status < 100 || status > 599 {
			return fail(e)
		}
		headers, e = readBHTTPFields(decrypted, known)
		if e != nil {
			return fail(e)
		}
		expected, e = contentLength(headers, req.Method, int(status))
		if e != nil {
			return fail(e)
		}
		if status >= 200 {
			break
		}
	}
	size, e := readVarint(decrypted, true)
	if e != nil {
		return fail(e)
	}
	if size > 1<<30 || (expected == 0 && size != 0) {
		return fail(fmt.Errorf("unexpected content size"))
	}
	responseBody := &bhttpBody{reader: decrypted, source: res.Body, known: known, remaining: size, expected: expected}
	var responseReader io.ReadCloser = responseBody
	if size == 0 {
		// Callers need not read empty bodies, so authenticate the final frame now.
		if _, e = responseBody.finish(); e != io.EOF {
			return fail(e)
		}
		res.Body.Close()
		responseReader = http.NoBody
		expected = 0
	}
	return &http.Response{StatusCode: int(status), Status: fmt.Sprintf("%d %s", status, http.StatusText(int(status))), Header: headers, Body: responseReader, ContentLength: expected, Request: req, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}, nil
}

type ohttpDecryptReader struct {
	reader  *bufio.Reader
	aead    cipher.AEAD
	nonce   []byte
	counter uint64
	total   uint64
	pending []byte
	final   bool
}

func (d *ohttpDecryptReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(d.pending) == 0 {
		if d.final {
			return 0, io.EOF
		}
		size, e := readVarint(d.reader, false)
		if e != nil {
			return 0, failure("ohttp.decryption_failed", e)
		}
		if d.counter >= 1<<32 || size > ohttpChunkSize+16 {
			return 0, failure("ohttp.decryption_failed", nil)
		}
		d.final = size == 0
		var encrypted []byte
		if d.final {
			encrypted, e = readBounded(d.reader, ohttpChunkSize+16)
		} else {
			encrypted, e = exact(d.reader, size, ohttpChunkSize+16)
		}
		if e != nil || len(encrypted) < 16 || (!d.final && len(encrypted) == 16) {
			return 0, failure("ohttp.decryption_failed", e)
		}
		n := append([]byte(nil), d.nonce...)
		for i := 0; i < 8; i++ {
			n[len(n)-1-i] ^= byte(d.counter >> (8 * i))
		}
		var aad []byte
		if d.final {
			aad = []byte("final")
		}
		d.pending, e = d.aead.Open(nil, n, encrypted, aad)
		if e != nil {
			return 0, failure("ohttp.decryption_failed", e)
		}
		d.counter++
		d.total += uint64(len(d.pending))
		if d.total > 1<<30 {
			return 0, failure("ohttp.decryption_failed", nil)
		}
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}
func readBHTTPFields(r *bufio.Reader, known bool) (http.Header, error) {
	headers := http.Header{}
	var section *bytes.Reader
	if known {
		size, e := readVarint(r, true)
		if e != nil {
			return nil, e
		}
		b, e := exact(r, size, 1<<20)
		if e != nil {
			return nil, e
		}
		section = bytes.NewReader(b)
		r = bufio.NewReader(section)
	}
	total := uint64(0)
	for {
		if known && section.Len()+r.Buffered() == 0 {
			return headers, nil
		}
		size, e := readVarint(r, !known && len(headers) == 0)
		if e != nil {
			return nil, e
		}
		if size == 0 {
			if known {
				return nil, fmt.Errorf("empty header")
			}
			return headers, nil
		}
		name, e := exact(r, size, 1<<20)
		if e != nil {
			return nil, e
		}
		size, e = readVarint(r, false)
		if e != nil {
			return nil, e
		}
		value, e := exact(r, size, 1<<20)
		if e != nil {
			return nil, e
		}
		total += uint64(len(name) + len(value))
		if total > 1<<20 {
			return nil, fmt.Errorf("header section too large")
		}
		for _, c := range strings.ToLower(string(name)) {
			if !strings.ContainsRune("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz", c) {
				return nil, fmt.Errorf("invalid header")
			}
		}
		if bytes.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("invalid header value")
		}
		headers.Add(string(name), string(value))
	}
}
func contentLength(headers http.Header, method string, status int) (int64, error) {
	length := int64(-1)
	for _, value := range headers.Values("Content-Length") {
		for _, s := range strings.Split(value, ",") {
			s = strings.TrimSpace(s)
			if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return -1, fmt.Errorf("invalid content length")
			}
			n, e := strconv.ParseInt(s, 10, 64)
			if e != nil || (length >= 0 && n != length) {
				return -1, fmt.Errorf("invalid content length")
			}
			length = n
		}
	}
	if length >= 0 && (status < 200 || status == 204) || (status == 205 && length > 0) {
		return -1, fmt.Errorf("unexpected content length")
	}
	if method == "HEAD" || status == 204 || status == 205 || status == 304 {
		return 0, nil
	}
	return length, nil
}

type bhttpBody struct {
	reader             *bufio.Reader
	source             io.ReadCloser
	known, first, done bool
	remaining          uint64
	received           int64
	expected           int64
}

func (b *bhttpBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.done {
		return 0, io.EOF
	}
	if b.remaining == 0 {
		if b.known && !b.first {
			return b.finish()
		}
		size, e := readVarint(b.reader, b.first)
		if e != nil {
			return 0, failure("ohttp.decryption_failed", e)
		}
		b.first = false
		if size == 0 {
			return b.finish()
		}
		if size > 1<<30 {
			return 0, failure("ohttp.decryption_failed", nil)
		}
		b.remaining = size
	}
	n, e := b.reader.Read(p[:min(uint64(len(p)), b.remaining)])
	b.remaining -= uint64(n)
	b.received += int64(n)
	if b.expected >= 0 && b.received > b.expected {
		return 0, failure("ohttp.decryption_failed", nil)
	}
	if e == io.EOF {
		e = io.ErrUnexpectedEOF
	}
	if e != nil {
		return n, failure("ohttp.decryption_failed", e)
	}
	return n, nil
}
func (b *bhttpBody) finish() (int, error) {
	b.done = true
	if b.expected >= 0 && b.received != b.expected {
		return 0, failure("ohttp.decryption_failed", nil)
	}
	if _, e := readBHTTPFields(b.reader, b.known); e != nil {
		return 0, failure("ohttp.decryption_failed", e)
	}
	for {
		buf, e := b.reader.ReadByte()
		if e == io.EOF {
			return 0, io.EOF
		}
		if e != nil || buf != 0 {
			return 0, failure("ohttp.decryption_failed", e)
		}
	}
}
func (b *bhttpBody) Close() error { return b.source.Close() }
