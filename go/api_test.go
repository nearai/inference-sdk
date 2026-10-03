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
