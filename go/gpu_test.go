package nearai

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestGPUVerifiesSignedVerdictAndNonce(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	n := strings.Repeat("11", 32)
	for _, variant := range []string{"ok", "wrong nonce", "rejected", "expired", "wrong issuer", "missing nbf", "verdict timeout", "jwks timeout"} {
		t.Run(variant, func(t *testing.T) {
			claims := jwt.MapClaims{
				"iss":                         "https://nras.attestation.nvidia.com",
				"iat":                         time.Now().Unix() - 1,
				"nbf":                         time.Now().Unix() - 1,
				"exp":                         time.Now().Unix() + 60,
				"eat_nonce":                   n,
				"x-nvidia-overall-att-result": true,
			}
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
				expectedPath := "/keys"
				if r.Method == "POST" {
					expectedPath = "/proxy/nras/v3/attest/gpu"
				}
				if r.URL.Path != expectedPath {
					t.Errorf("request path = %s, want %s", r.URL.Path, expectedPath)
				}
				if (variant == "verdict timeout" && r.Method == "POST") || (variant == "jwks timeout" && r.Method == "GET") {
					w.WriteHeader(http.StatusRequestTimeout)
					return
				}
				if r.Method == "POST" {
					json.NewEncoder(w).Encode([]any{[]any{"JWT", signed}, map[string]any{}})
				} else {
					json.NewEncoder(w).Encode(map[string]any{
						"keys": []any{
							map[string]any{
								"kty": "EC",
								"crv": "P-384",
								"kid": "test",
								"alg": "ES384",
								"x":   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 48))),
								"y":   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 48))),
							},
						},
					})
				}
			}))
			defer server.Close()
			verifier := CreateGPUEvidenceVerifier(GPUVerifierOptions{
				NRASBaseURL: server.URL + "/proxy/nras/",
				JWKSURL:     server.URL + "/keys",
			})
			e = verifier(context.Background(), `{"nonce":"`+n+`"}`)
			if strings.HasSuffix(variant, "timeout") {
				var sdkErr *Error
				if !errors.As(e, &sdkErr) || !sdkErr.Retryable {
					t.Fatalf("timeout is not retryable: %v", e)
				}
			}
			if variant == "ok" && e != nil {
				t.Fatal(e)
			}
			if variant != "ok" && e == nil {
				t.Fatal("bad verdict accepted")
			}
		})
	}
}

type gpuTestTransport func(*http.Request) (*http.Response, error)

func (f gpuTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestGPUServiceURLs(t *testing.T) {
	for _, tc := range []struct {
		name, baseURL, attestURL string
	}{
		{"defaults", "", "https://cloud.near.ai/api/proxy/nras/v3/attest/gpu"},
		{"custom base", "https://attestation.example/nras", "https://attestation.example/nras/v3/attest/gpu"},
		{"trailing slash", "https://attestation.example/nras/", "https://attestation.example/nras/v3/attest/gpu"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests []string
			client := &http.Client{Transport: gpuTestTransport(func(r *http.Request) (*http.Response, error) {
				requests = append(requests, r.Method+" "+r.URL.String())
				body := `[["JWT","invalid-test-token"]]`
				if r.Method == "GET" {
					body = `{"keys":[]}`
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}
			verifier := CreateGPUEvidenceVerifier(GPUVerifierOptions{NRASBaseURL: tc.baseURL, HTTPClient: client})
			err := verifier(context.Background(), `{"nonce":"`+strings.Repeat("11", 32)+`"}`)
			var sdkErr *Error
			if !errors.As(err, &sdkErr) || sdkErr.Code != "gpu.jwt_verification_failed" {
				t.Fatalf("expected the fetched token to fail verification, got %v", err)
			}
			expected := []string{
				"POST " + tc.attestURL,
				"GET https://nras.attestation.nvidia.com/.well-known/jwks.json",
			}
			if !slices.Equal(requests, expected) {
				t.Fatalf("requests = %v, want %v", requests, expected)
			}
		})
	}
}
