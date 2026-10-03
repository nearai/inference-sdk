package nearai

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	jwt "github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGPUVerifiesSignedVerdictAndNonce(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	n := strings.Repeat("11", 32)
	for _, variant := range []string{"ok", "wrong nonce", "rejected", "expired", "wrong issuer", "missing nbf"} {
		t.Run(variant, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": "https://nras.attestation.nvidia.com", "iat": time.Now().Unix() - 1, "nbf": time.Now().Unix() - 1, "exp": time.Now().Unix() + 60, "eat_nonce": n, "x-nvidia-overall-att-result": true}
			switch variant {
			case "wrong nonce":
				claims["eat_nonce"] = strings.Repeat("22", 32)
			case "rejected":
				claims["x-nvidia-overall-att-result"] = false
			case "expired":
				claims["exp"] = time.Now().Unix() - 2
			case "wrong issuer":
				claims["iss"] = "attacker"
			case "missing nbf":
				delete(claims, "nbf")
			}
			token := jwt.NewWithClaims(jwt.SigningMethodES384, claims)
			token.Header["kid"] = "test"
			signed, e := token.SignedString(key)
			if e != nil {
				t.Fatal(e)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					json.NewEncoder(w).Encode([]any{[]any{"JWT", signed}, map[string]any{}})
				} else {
					json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-384", "kid": "test", "alg": "ES384", "x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 48))), "y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 48)))}}})
				}
			}))
			defer server.Close()
			e = CreateGPUEvidenceVerifier(GPUVerifierOptions{NRASURL: server.URL, JWKSURL: server.URL})(context.Background(), `{"nonce":"`+n+`"}`)
			if variant == "ok" && e != nil {
				t.Fatal(e)
			}
			if variant != "ok" && e == nil {
				t.Fatal("bad verdict accepted")
			}
		})
	}
}
