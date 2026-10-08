package nearai

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSignatureAPIErrorBoundaries(t *testing.T) {
	for _, tt := range []struct{ body, code string }{
		{`{"error_code":"pending","message":"Try later"}`, "api.completion_signature_unavailable"},
		{`{"error_code":"pending","message":"Try later","text":"abc"}`, "api.invalid_response"},
		{`{}`, "api.invalid_response"},
		{`{"text":"abc","signature":"ff","signing_algo":"ed25519","signing_address":"ff","signature_kind":"gateway"}`, "api.invalid_response"},
		{`{"text":"abc","signature":"ff","signing_algo":"ed25519","signing_address":"ff","signature_kind":"unknown"}`, "api.invalid_response"},
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
