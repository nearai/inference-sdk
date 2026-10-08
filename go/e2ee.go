package nearai

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"unicode/utf8"

	"filippo.io/edwards25519"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type E2EEModelKey struct {
	SigningAlgo SigningAlgo
	PublicKey   string
}
type e2eeKey struct {
	algo   SigningAlgo
	public string
	secret []byte
}

// PreparedE2EEChatRequest encrypts for a caller-authenticated key. This helper
// does not verify that key or completion signatures. Retain original wire bytes.
type PreparedE2EEChatRequest struct {
	Request *http.Request
	key     e2eeKey
}

func newE2EEKey(algo SigningAlgo) (e2eeKey, error) {
	if algo == ECDSA {
		key, e := secp.GeneratePrivateKey()
		if e != nil {
			return e2eeKey{}, e
		}
		return e2eeKey{algo, hex.EncodeToString(key.PubKey().SerializeUncompressed()[1:]), key.Serialize()}, nil
	}
	if algo != Ed25519 {
		return e2eeKey{}, failure("input.invalid", nil)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e2eeKey{}, e
	}
	h := sha512.Sum512(priv.Seed())
	secret := append([]byte(nil), h[:32]...)
	secret[0] &= 248
	secret[31] &= 127
	secret[31] |= 64
	return e2eeKey{algo, hex.EncodeToString(pub), secret}, nil
}
func deriveKey(shared []byte, algo SigningAlgo) ([]byte, error) {
	key := make([]byte, 32)
	_, e := io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte(string(algo)+"_encryption")), key)
	return key, e
}
func encryptText(text string, key E2EEModelKey) (string, error) {
	pub, e := unhex(key.PublicKey)
	if e != nil {
		return "", failure("e2ee.model_public_key_invalid", e)
	}
	var prefix, shared []byte
	var aead cipher.AEAD
	switch key.SigningAlgo {
	case Ed25519:
		point, e := new(edwards25519.Point).SetBytes(pub)
		if e != nil {
			return "", failure("e2ee.model_public_key_invalid", e)
		}
		target, e := ecdh.X25519().NewPublicKey(point.BytesMontgomery())
		if e != nil {
			return "", e
		}
		ephemeral, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return "", e
		}
		shared, e = ephemeral.ECDH(target)
		if e != nil {
			return "", e
		}
		prefix = ephemeral.PublicKey().Bytes()
		derived, e := deriveKey(shared, Ed25519)
		if e != nil {
			return "", e
		}
		aead, e = chacha20poly1305.NewX(derived)
		if e != nil {
			return "", e
		}
	case ECDSA:
		if len(pub) == 64 {
			pub = append([]byte{4}, pub...)
		}
		target, e := secp.ParsePubKey(pub)
		if e != nil || len(pub) != 65 {
			return "", failure("e2ee.model_public_key_invalid", e)
		}
		ephemeral, e := secp.GeneratePrivateKey()
		if e != nil {
			return "", e
		}
		shared = secp.GenerateSharedSecret(ephemeral, target)
		prefix = ephemeral.PubKey().SerializeUncompressed()
		derived, e := deriveKey(shared, ECDSA)
		if e != nil {
			return "", e
		}
		block, e := aes.NewCipher(derived)
		if e != nil {
			return "", e
		}
		aead, e = cipher.NewGCM(block)
		if e != nil {
			return "", e
		}
	default:
		return "", failure("e2ee.model_public_key_invalid", nil)
	}
	n := make([]byte, aead.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return "", e
	}
	out := append(prefix, n...)
	out = aead.Seal(out, n, []byte(text), nil)
	return hex.EncodeToString(out), nil
}
func decryptText(text string, key e2eeKey) (string, error) {
	if text == "" {
		return "", nil
	}
	raw, e := unhex(text)
	if e != nil {
		return "", failure("e2ee.decryption_failed", e)
	}
	prefix, nonceSize := 32, 24
	if key.algo == ECDSA {
		prefix, nonceSize = 65, 12
	}
	if len(raw) < prefix+nonceSize+16 {
		return "", failure("e2ee.decryption_failed", nil)
	}
	var shared []byte
	var aead cipher.AEAD
	if key.algo == Ed25519 {
		pub, e := ecdh.X25519().NewPublicKey(raw[:prefix])
		if e != nil {
			return "", e
		}
		priv, e := ecdh.X25519().NewPrivateKey(key.secret)
		if e != nil {
			return "", e
		}
		shared, e = priv.ECDH(pub)
		if e != nil {
			return "", failure("e2ee.decryption_failed", e)
		}
		derived, e := deriveKey(shared, Ed25519)
		if e != nil {
			return "", e
		}
		aead, e = chacha20poly1305.NewX(derived)
		if e != nil {
			return "", e
		}
	} else {
		if raw[0] != 4 {
			return "", failure("e2ee.decryption_failed", nil)
		}
		pub, e := secp.ParsePubKey(raw[:prefix])
		if e != nil {
			return "", failure("e2ee.decryption_failed", e)
		}
		shared = secp.GenerateSharedSecret(secp.PrivKeyFromBytes(key.secret), pub)
		derived, e := deriveKey(shared, ECDSA)
		if e != nil {
			return "", e
		}
		block, e := aes.NewCipher(derived)
		if e != nil {
			return "", e
		}
		aead, e = cipher.NewGCM(block)
		if e != nil {
			return "", e
		}
	}
	plaintext, e := aead.Open(nil, raw[prefix:prefix+nonceSize], raw[prefix+nonceSize:], nil)
	if e != nil || !utf8.Valid(plaintext) {
		return "", failure("e2ee.decryption_failed", e)
	}
	return string(plaintext), nil
}
func objects(v any) []map[string]any {
	var out []map[string]any
	if list, ok := v.([]any); ok {
		for _, item := range list {
			if obj, ok := item.(map[string]any); ok {
				out = append(out, obj)
			}
		}
	}
	return out
}
func object(v any) map[string]any { o, _ := v.(map[string]any); return o }
func transformFields(target map[string]any, transform func(string) (string, error), fields ...string) error {
	for _, field := range fields {
		if text, ok := target[field].(string); ok {
			v, e := transform(text)
			if e != nil {
				return e
			}
			target[field] = v
		}
	}
	return nil
}
func encryptChat(body map[string]any, key E2EEModelKey) error {
	f := func(s string) (string, error) { return encryptText(s, key) }
	for _, m := range objects(body["messages"]) {
		if list, ok := m["content"].([]any); ok {
			encoded, e := json.Marshal(list)
			if e != nil {
				return e
			}
			m["content"] = string(encoded)
		}
		if e := transformFields(m, f, "content", "reasoning_content", "reasoning", "name", "refusal"); e != nil {
			return e
		}
		if e := transformFields(object(m["audio"]), f, "data"); e != nil {
			return e
		}
		for _, call := range objects(m["tool_calls"]) {
			if e := transformFields(object(call["function"]), f, "name", "arguments"); e != nil {
				return e
			}
		}
		if e := transformFields(object(m["function_call"]), f, "name", "arguments"); e != nil {
			return e
		}
	}
	for _, tool := range objects(body["tools"]) {
		fn := object(tool["function"])
		if e := transformFields(fn, f, "name", "description"); e != nil {
			return e
		}
		if p, ok := fn["parameters"]; ok {
			b, e := json.Marshal(p)
			if e != nil {
				return e
			}
			fn["parameters"], e = f(string(b))
			if e != nil {
				return e
			}
		}
	}
	if e := transformFields(object(object(body["tool_choice"])["function"]), f, "name"); e != nil {
		return e
	}
	return transformFields(object(body["function_call"]), f, "name")
}
func decryptChat(body map[string]any, key e2eeKey, stream bool) error {
	f := func(s string) (string, error) { return decryptText(s, key) }
	field := "message"
	if stream {
		field = "delta"
	}
	for _, choice := range objects(body["choices"]) {
		m := object(choice[field])
		if e := transformFields(m, f, "content", "reasoning_content", "reasoning", "refusal"); e != nil {
			return e
		}
		for _, part := range objects(m["content"]) {
			if e := transformFields(part, f, "text"); e != nil {
				return e
			}
		}
		if e := transformFields(object(m["audio"]), f, "data"); e != nil {
			return e
		}
		for _, call := range objects(m["tool_calls"]) {
			if e := transformFields(object(call["function"]), f, "name", "arguments"); e != nil {
				return e
			}
		}
		if e := transformFields(object(m["function_call"]), f, "name", "arguments"); e != nil {
			return e
		}
		if stream {
			if e := transformFields(object(m["nearai_tool_result"]), f, "output"); e != nil {
				return e
			}
		}
		for _, field := range []string{"content", "refusal"} {
			if e := decryptLogprobs(object(choice["logprobs"])[field], f); e != nil {
				return e
			}
		}
	}
	return nil
}
func decryptLogprobs(value any, f func(string) (string, error)) error {
	for _, entry := range objects(value) {
		if e := transformFields(entry, f, "token"); e != nil {
			return e
		}
		if text, ok := entry["bytes"].(string); ok {
			s, e := f(text)
			if e != nil {
				return e
			}
			var v any
			if e = json.Unmarshal([]byte(s), &v); e != nil {
				return failure("e2ee.decryption_failed", e)
			}
			entry["bytes"] = v
		}
		if e := decryptLogprobs(entry["top_logprobs"], f); e != nil {
			return e
		}
	}
	return nil
}
func removeE2EEHeaders(h http.Header) {
	for _, name := range []string{"X-Signing-Algo", "X-Client-Pub-Key", "X-Model-Pub-Key", "X-Encryption-Version", "X-Encrypt-All-Fields"} {
		h.Del(name)
	}
}
func removeBodyHeaders(h http.Header) {
	for _, name := range []string{"Content-Length", "Transfer-Encoding", "Trailer", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "Content-Encoding", "ETag", "Last-Modified"} {
		h.Del(name)
	}
}
func decodeObject(b []byte) (map[string]any, error) {
	var v map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := d.Decode(&v); e != nil || v == nil || !json.Valid(b) || !utf8.Valid(b) {
		return nil, failure("api.invalid_response", e)
	}
	return v, nil
}
func PrepareE2EEChatRequest(req *http.Request, key E2EEModelKey) (*PreparedE2EEChatRequest, error) {
	if req.Method != "POST" || req.Body == nil {
		return nil, failure("api.invalid_input", nil)
	}
	b, e := readBounded(req.Body, 64<<20)
	if e != nil {
		return nil, e
	}
	body, e := decodeObject(b)
	if e != nil {
		return nil, e
	}
	if model, ok := body["model"].(string); !ok || model == "" {
		return nil, failure("api.invalid_input", nil)
	}
	clientKey, e := newE2EEKey(key.SigningAlgo)
	if e != nil {
		return nil, e
	}
	if e = encryptChat(body, key); e != nil {
		return nil, e
	}
	encoded, e := json.Marshal(body)
	if e != nil {
		return nil, e
	}
	r := req.Clone(req.Context())
	r.Header = make(http.Header)
	for k, v := range req.Header {
		r.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
	}
	r.Body = io.NopCloser(bytes.NewReader(encoded))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(encoded)), nil }
	r.ContentLength = int64(len(encoded))
	r.TransferEncoding = nil
	r.Trailer = nil
	removeBodyHeaders(r.Header)
	removeE2EEHeaders(r.Header)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Signing-Algo", string(key.SigningAlgo))
	r.Header.Set("X-Client-Pub-Key", clientKey.public)
	r.Header.Set("X-Model-Pub-Key", key.PublicKey)
	r.Header.Set("X-Encrypt-All-Fields", "true")
	r.Header.Set(NoAliasingHeader, "true")
	if key.SigningAlgo == Ed25519 {
		r.Header.Set("X-Encryption-Version", "2")
	}
	return &PreparedE2EEChatRequest{r, clientKey}, nil
}
func (p *PreparedE2EEChatRequest) DecryptJSON(wire []byte) ([]byte, error) {
	body, e := decodeObject(wire)
	if e != nil {
		return nil, e
	}
	if e = decryptChat(body, p.key, false); e != nil {
		return nil, e
	}
	return json.Marshal(body)
}
