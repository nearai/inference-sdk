package nearai

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

func writeEncodedResponse(t *testing.T, w http.ResponseWriter, body []byte, encoding string) {
	t.Helper()
	if encoding != "" {
		var compressed bytes.Buffer
		var writer io.WriteCloser
		if encoding == "gzip" {
			writer = gzip.NewWriter(&compressed)
		} else {
			writer = brotli.NewWriter(&compressed)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		body = compressed.Bytes()
		w.Header().Set("Content-Encoding", encoding)
		w.Header().Set("Content-Length", itoa(len(body)))
	}
	_, _ = w.Write(body)
}

func TestSignatureAPIErrorBoundaries(t *testing.T) {
	for _, tt := range []struct{ body, code string }{
		{`{"error_code":"pending","message":"Try later"}`, "api.completion_signature_unavailable"},
		{`{"error_code":"pending","message":"Try later","text":"abc"}`, "api.invalid_response"},
		{`{}`, "api.invalid_response"},
		{
			`{"text":"abc","signature":"ff","signing_algo":"ed25519","signing_address":"ff","signature_kind":"gateway"}`,
			"api.invalid_response",
		},
		{
			`{"text":"abc","signature":"ff","signing_algo":"ed25519","signing_address":"ff","signature_kind":"unknown"}`,
			"api.invalid_response",
		},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, tt.body) }))
		c, e := NewAttestationClient(ClientOptions{BaseURL: server.URL})
		if e != nil {
			t.Fatal(e)
		}
		_, e = c.FetchCompletionSignature(context.Background(), "test", Ed25519)
		server.Close()
		requireCode(t, e, tt.code)
		if tt.code == "api.completion_signature_unavailable" {
			sdk := e.(*Error)
			if sdk.Details["providerErrorCode"] != "pending" || sdk.Details["providerMessage"] != "Try later" {
				t.Fatal(sdk.Details)
			}
		}
	}
}

func TestHTTPStatusRetryabilityDependsOnResource(t *testing.T) {
	for _, status := range []int{400, 401, 404, 408, 425, 429, 500} {
		t.Run(itoa(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			c, err := NewAttestationClient(ClientOptions{BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = c.get(context.Background(), "model/test", nil)
			requireCode(t, err, "api.http_status")
			want := status == 408 || status == 425 || status == 429 || status >= 500
			if err.(*Error).Retryable != want {
				t.Fatalf("model status %d: %v", status, err)
			}
			_, err = c.FetchCompletionSignature(context.Background(), "test", Ed25519)
			requireCode(t, err, "api.http_status")
			if err.(*Error).Retryable != (want || status == 404) {
				t.Fatalf("signature status %d: %v", status, err)
			}
		})
	}
}

func TestAddressOnlyAttestationFilter(t *testing.T) {
	for _, length := range []int{20, 32} {
		address := strings.Repeat("ab", length)
		q, err := optionsQuery(FetchOptions{SigningAddress: address})
		if err != nil || q.Get("signing_address") != address || q.Get("signing_algo") != "" {
			t.Fatalf("%v %v", q, err)
		}
	}
	if _, err := optionsQuery(FetchOptions{SigningAddress: "ab"}); err == nil {
		t.Fatal("invalid address accepted")
	}
	if _, err := optionsQuery(FetchOptions{SigningAlgo: Ed25519, SigningAddress: strings.Repeat("ab", 20)}); err == nil {
		t.Fatal("algorithm length mismatch accepted")
	}
}

func TestStructuralAttestationComparison(t *testing.T) {
	a := Attestation{EventLog: json.RawMessage(`[{"imr":3,"nested":{"b":2,"a":9007199254740993}}]`)}
	b := a
	b.EventLog = json.RawMessage(`[ {"nested": {"a":9007199254740993,"b":2}, "imr":3} ]`)
	if !sameAttestation(a, b) {
		t.Fatal("JSON serialization changed report identity")
	}
	b.EventLog = json.RawMessage(`[{"imr":3,"nested":{"b":2,"a":9007199254740992}}]`)
	if sameAttestation(a, b) {
		t.Fatal("different integer values matched")
	}
	a.EventLog = json.RawMessage(`[1,2]`)
	b.EventLog = json.RawMessage(`[2,1]`)
	if sameAttestation(a, b) {
		t.Fatal("array order ignored")
	}
}

func TestReadBoundedMaximumLimit(t *testing.T) {
	body, err := readBounded(strings.NewReader("completion"), math.MaxInt64)
	if err != nil || string(body) != "completion" {
		t.Fatalf("maximum limit discarded body: %q, %v", body, err)
	}
}

func TestOptionalAPIKeyAndAttestationHeaders(t *testing.T) {
	for _, direct := range []bool{false, true} {
		for _, apiKey := range []string{"", "test"} {
			for _, customHeaders := range []bool{false, true} {
				t.Run(fmt.Sprintf("direct=%t/key=%s/headers=%t", direct, apiKey, customHeaders), func(t *testing.T) {
					fixture := newFakeCloud(t)
					fixture.direct = direct
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if customHeaders && r.Header.Get("X-Tenant") != "tenant" {
							t.Error("custom header missing")
						}
						if r.URL.Path == "/v1/attestation/report" {
							fixture.ServeHTTP(w, r)
							return
						}
						want := ""
						if apiKey != "" {
							want = "Bearer test"
						} else if customHeaders {
							want = "Bearer custom"
						}
						if r.Header.Get("Authorization") != want {
							t.Errorf("signature authorization = %q, want %q", r.Header.Get("Authorization"), want)
						}
						json.NewEncoder(w).Encode(map[string]string{
							"text": "request:response", "signature": "aa", "signature_kind": "provider_tee",
							"signing_algo": "ed25519", "signing_address": strings.Repeat("22", 32),
						})
					}))
					defer server.Close()
					options := ClientOptions{BaseURL: server.URL + "/v1", APIKey: apiKey}
					if customHeaders {
						options.Headers = http.Header{"Authorization": {"Bearer custom"}, "Api-Key": {"api-key"}, "X-Api-Key": {"x-api-key"}, "X-Tenant": {"tenant"}}
					}
					constructor := NewAttestationClient
					if direct {
						constructor = NewDirectAttestationClient
					}
					client, err := constructor(options)
					if err != nil {
						t.Fatal(err)
					}
					ctx := context.Background()
					if !direct {
						if _, err = client.FetchGatewayAttestation(ctx, FetchOptions{DisableTLSBinding: true}); err != nil {
							t.Fatal(err)
						}
					}
					if _, err = client.FetchModelAttestations(ctx, "canonical/model", FetchOptions{}); err != nil {
						t.Fatal(err)
					}
					if _, err = client.FetchCompletionSignature(ctx, "test", Ed25519); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}
