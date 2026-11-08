package nearai

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPinnedTLSProtectsChatAndEvidenceBeforeSending(t *testing.T) {
	for _, operation := range []string{"chat", "metadata", "model", "signature", "gateway"} {
		for _, condition := range []string{"valid", "wrong pin", "wrong hostname", "untrusted chain"} {
			t.Run(operation+"/"+condition, func(t *testing.T) {
				var requests atomic.Int32
				var fingerprint string
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					wantAuth := "Bearer test"
					if operation == "gateway" {
						wantAuth = ""
					}
					if r.Header.Get("Authorization") != wantAuth {
						t.Error("incorrect authorization")
					}
					report := map[string]any{
						"request_nonce": r.URL.Query().Get("nonce"), "signing_algo": "ed25519",
						"signing_address": strings.Repeat("11", 32), "intel_quote": "aa",
						"event_log": []any{}, "report_data": strings.Repeat("00", 64),
						"info": map[string]any{"tcb_info": map[string]any{"app_compose": "{}"}},
					}
					if operation == "gateway" {
						report["tls_cert_fingerprint"] = fingerprint
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"metadata":           map[string]any{"providerType": "vllm", "attestationSupported": true},
						"model_attestations": []any{report}, "gateway_attestation": report,
						"text": "request:response", "signature": strings.Repeat("00", 64),
						"signing_algo": "ed25519", "signing_address": strings.Repeat("11", 32),
						"signature_kind": "provider_tee",
					})
				}))
				defer server.Close()
				server.Config.ErrorLog = log.New(io.Discard, "", 0)
				sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
				fingerprint = hex.EncodeToString(sum[:])
				base := server.Client().Transport.(*http.Transport).Clone()
				base.TLSClientConfig = base.TLSClientConfig.Clone()
				pin := fingerprint
				switch condition {
				case "wrong pin":
					pin = strings.Repeat("00", 32)
				case "wrong hostname":
					base.TLSClientConfig.ServerName = "other.invalid"
				case "untrusted chain":
					base.TLSClientConfig.RootCAs = x509.NewCertPool()
				}
				transport, err := NewPinnedTransport(base, pin)
				if err != nil {
					t.Fatal(err)
				}
				defer transport.CloseIdleConnections()
				httpClient := &http.Client{Transport: transport}
				api, err := NewAttestationClient(ClientOptions{BaseURL: server.URL + "/v1", APIKey: "test", HTTPClient: httpClient})
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				switch operation {
				case "metadata":
					_, err = api.FetchModelMetadata(ctx, "model")
				case "model":
					_, err = api.FetchModelAttestations(ctx, "model", FetchOptions{})
				case "signature":
					_, err = api.FetchCompletionSignature(ctx, "completion", Ed25519)
				case "gateway":
					var fetched FetchedGatewayAttestation
					fetched, err = api.FetchGatewayAttestation(ctx, FetchOptions{})
					if err == nil && fetched.ClientBinding.SPKIFingerprint != fingerprint {
						t.Fatal("Gateway peer was not captured from the evidence connection")
					}
				case "chat":
					request, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/v1/chat/completions", strings.NewReader("private prompt"))
					request.Header.Set("Authorization", "Bearer test")
					var response *http.Response
					response, err = httpClient.Do(request)
					if response != nil {
						response.Body.Close()
					}
				}
				if condition == "valid" {
					if err != nil || requests.Load() != 1 {
						t.Fatalf("valid connection: requests=%d, error=%v", requests.Load(), err)
					}
				} else {
					if err == nil || requests.Load() != 0 {
						t.Fatalf("failed TLS sent HTTP: requests=%d, error=%v", requests.Load(), err)
					}
					if condition == "wrong pin" {
						requireCode(t, err, "binding.spki_fingerprint_mismatch")
					}
				}
			})
		}
	}
}
