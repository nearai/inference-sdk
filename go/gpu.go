package nearai

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	jwt "github.com/golang-jwt/jwt/v5"
	"math"
	"math/big"
	"net/http"
	"time"
)

type GPUVerifierOptions struct {
	NRASURL, JWKSURL string
	HTTPClient       *http.Client
}

// CreateGPUEvidenceVerifier authenticates NVIDIA's ES384 overall verdict, issuer,
// validity interval and nonce. A custom JWKS URL must be a trusted key source.
func CreateGPUEvidenceVerifier(o GPUVerifierOptions) GPUEvidenceVerifier {
	if o.NRASURL == "" {
		o.NRASURL = "https://nras.attestation.nvidia.com/v3/attest/gpu"
	}
	if o.JWKSURL == "" {
		o.JWKSURL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"
	}
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: time.Minute}
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &clone
	return func(ctx context.Context, payload string) error {
		var input struct {
			Nonce string `json:"nonce"`
		}
		if json.Unmarshal([]byte(payload), &input) != nil {
			return failure("gpu.nras_response_invalid", nil)
		}
		if _, e := hexSize(input.Nonce, 32); e != nil {
			return e
		}
		fetch := func(method, target string, body []byte) ([]byte, error) {
			req, e := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
			if e != nil {
				return nil, e
			}
			req.Header.Set("Content-Type", "application/json")
			res, e := client.Do(req)
			if e != nil {
				return nil, &Error{Code: "gpu.nras_request_failed", Retryable: true, Cause: e}
			}
			defer res.Body.Close()
			if res.StatusCode < 200 || res.StatusCode >= 300 {
				return nil, &Error{Code: "gpu.nras_request_failed", Retryable: res.StatusCode == 429 || res.StatusCode >= 500, Details: map[string]any{"status": res.StatusCode}}
			}
			return readBounded(res.Body, 8<<20)
		}
		raw, e := fetch("POST", o.NRASURL, []byte(payload))
		if e != nil {
			return e
		}
		var result []json.RawMessage
		if json.Unmarshal(raw, &result) != nil || len(result) < 1 {
			return failure("gpu.nras_response_invalid", nil)
		}
		var entry []json.RawMessage
		if json.Unmarshal(result[0], &entry) != nil || len(entry) < 2 {
			return failure("gpu.nras_response_invalid", nil)
		}
		var label, token string
		if json.Unmarshal(entry[0], &label) != nil || label != "JWT" || json.Unmarshal(entry[1], &token) != nil || token == "" {
			return failure("gpu.nras_response_invalid", nil)
		}
		raw, e = fetch("GET", o.JWKSURL, nil)
		if e != nil {
			return e
		}
		var jwks struct {
			Keys []struct{ Kty, Crv, X, Y, Kid, Alg, Use string }
		}
		if json.Unmarshal(raw, &jwks) != nil {
			return failure("gpu.nras_response_invalid", nil)
		}
		claims := jwt.MapClaims{}
		parsed, e := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
			kid, ok := t.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, failure("gpu.jwt_verification_failed", nil)
			}
			var selected *ecdsa.PublicKey
			for _, key := range jwks.Keys {
				if key.Kid != kid || key.Kty != "EC" || key.Crv != "P-384" || (key.Alg != "" && key.Alg != "ES384") || (key.Use != "" && key.Use != "sig") {
					continue
				}
				x, e := base64.RawURLEncoding.DecodeString(key.X)
				if e != nil {
					return nil, e
				}
				y, e := base64.RawURLEncoding.DecodeString(key.Y)
				if e != nil {
					return nil, e
				}
				p := &ecdsa.PublicKey{Curve: elliptic.P384(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
				if len(x) != 48 || len(y) != 48 || !p.Curve.IsOnCurve(p.X, p.Y) || selected != nil {
					return nil, failure("gpu.jwt_verification_failed", nil)
				}
				selected = p
			}
			if selected == nil {
				return nil, failure("gpu.jwt_verification_failed", nil)
			}
			return selected, nil
		}, jwt.WithValidMethods([]string{"ES384"}), jwt.WithIssuer("https://nras.attestation.nvidia.com"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
		if e != nil || !parsed.Valid {
			return failure("gpu.jwt_verification_failed", e)
		}
		for _, field := range []string{"iat", "nbf", "exp"} {
			if number, ok := claims[field].(float64); !ok || math.Trunc(number) != number {
				return failure("gpu.jwt_verification_failed", nil)
			}
		}
		n, ok := claims["eat_nonce"].(string)
		if !ok || !sameHex(n, input.Nonce) {
			return failure("gpu.jwt_verification_failed", nil)
		}
		verdict, ok := claims["x-nvidia-overall-att-result"].(bool)
		if !ok || !verdict {
			return failure("gpu.attestation_rejected", nil)
		}
		return nil
	}
}
