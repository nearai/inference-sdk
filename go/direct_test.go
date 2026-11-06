package nearai

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

func TestDirectOHTTPSelectsServingSigner(t *testing.T)           { testDirectRoute(t, true, false) }
func TestDirectDeploymentVerifierChecksEveryReport(t *testing.T) { testDirectRoute(t, false, true) }
func testDirectRoute(t *testing.T, ohttp, sharedSigner bool) {
	a, qa, _ := attestationFixture(t, Ed25519)
	b, qb, priv := attestationFixture(t, Ed25519)
	a.InstanceID, b.InstanceID = "other", "serving"
	if sharedSigner {
		a.Signer, a.SigningPublicKey = b.Signer, b.SigningPublicKey
		copy(qa.ReportData[:32], qb.ReportData[:32])
	}
	request := []byte(`{"model":"canonical/model"}`)
	response := []byte(`{"id":"chat"}`)
	text := "canonical/model:" + hashText(request) + ":" + hashText(response)
	pub, _, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if e != nil {
		t.Fatal(e)
	}
	pk, _ := pub.MarshalBinary()
	config := append([]byte{1, 0, 32}, pk...)
	config = append(config, 0, 4, 0, 1, 0, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/signature/chat" {
			json.NewEncoder(w).Encode(map[string]any{
				"text": text, "signature": hex.EncodeToString(ed25519.Sign(priv, []byte(text))),
				"signing_algo": "ed25519", "signing_address": b.Signer.SigningAddress,
			})
			return
		}
		if r.URL.Query().Get("include_tls_fingerprint") != "false" {
			t.Error("direct TLS must be disabled")
		}
		n := r.URL.Query().Get("nonce")
		makeReport := func(a Attestation, q QuoteVerificationResult) map[string]any {
			q.ReportData = append([]byte(nil), q.ReportData...)
			nonce, _ := unhex(n)
			copy(q.ReportData[32:], nonce)
			encoded, _ := json.Marshal(q)
			return map[string]any{
				"model_name":         "canonical/model",
				"request_nonce":      n,
				"signing_algo":       "ed25519",
				"signing_address":    a.Signer.SigningAddress,
				"signing_public_key": a.SigningPublicKey,
				"intel_quote":        string(encoded),
				"event_log":          a.EventLog,
				"info":               map[string]any{"instance_id": a.InstanceID, "tcb_info": map[string]any{"app_compose": a.AppCompose}},
			}
		}
		first, serving := makeReport(a, qa), makeReport(b, qb)
		root := map[string]any{}
		for k, v := range serving {
			root[k] = v
		}
		// Reformat the nested event log only in the top-level serving report.
		var log bytes.Buffer
		if err := json.Indent(&log, b.EventLog, "", "  "); err != nil {
			t.Error(err)
		}
		root["event_log"] = json.RawMessage(log.Bytes())
		root["all_attestations"] = []any{first, serving}
		root["ohttp_attestation"] = OHTTPAttestation{
			Ed25519,
			b.Signer.SigningAddress,
			hex.EncodeToString(config),
			hex.EncodeToString(ed25519.Sign(priv, config)),
		}
		json.NewEncoder(w).Encode(root)
	}))
	defer server.Close()
	calls := 0
	check := func(context.Context, MeasuredDeployment) error { calls++; return nil }
	client, e := NewDirectInferenceClient(DirectInferenceOptions{
		InferenceOptions: InferenceOptions{
			ClientOptions:     ClientOptions{BaseURL: server.URL + "/v1"},
			E2EE:              true,
			OHTTP:             ohttp,
			ModelVerification: VerificationOptions{QuoteVerifier: fakeQuote, DeploymentVerifier: check},
		},
	})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	preflight, e := client.Verify(context.Background(), "canonical/model")
	if e != nil {
		t.Fatal(e)
	}
	var _ DirectAttestationVerificationResult = preflight
	if calls != 2 || len(preflight.Attestations) != 2 || preflight.Attestations[0].DeploymentProvenance != "verified" || preflight.Attestations[1].DeploymentProvenance != "verified" {
		t.Fatal("deployment verifier must check every report")
	}
	if preflight.ServingAttestation.InstanceID != "serving" || len(preflight.SPKIFingerprints) != 0 || preflight.VerifiedAt.IsZero() {
		t.Fatal("preflight must retain the actual serving report without enabling TLS binding")
	}
	preflight.ServingAttestation.InstanceID = "changed"
	preflight.Attestations[0].InstanceID = "changed"
	preflight.Attestations[0].Deployment.AppCompose = "changed"
	cached, err := client.Verify(context.Background(), "canonical/model")
	if err != nil || calls != 2 || !cached.VerifiedAt.Equal(preflight.VerifiedAt) || cached.ServingAttestation.InstanceID != "serving" || cached.Attestations[0].InstanceID != "other" || cached.Attestations[0].Deployment.AppCompose == "changed" {
		t.Fatal("Direct preflight must return independent snapshots of the original verification", err)
	}
	session, err := client.client.getSession(context.Background(), "canonical/model")
	if err != nil {
		t.Fatal(err)
	}
	if err = client.client.register("chat", request, response, session, false, client.client.responseCacheGeneration()); err != nil {
		t.Fatal(err)
	}
	receipt, err := client.VerifyResponse(context.Background(), "chat")
	if err != nil {
		t.Fatal(err)
	}
	var _ VerifiedDirectCompletionResult = receipt
	if sharedSigner {
		if len(receipt.Attestations) != 2 || receipt.Attestations[0].InstanceID != "other" || receipt.Attestations[1].InstanceID != "serving" {
			t.Fatal("receipt must preserve every report sharing the signer")
		}
	} else if len(receipt.Attestations) != 1 || receipt.Attestations[0].InstanceID != "serving" {
		t.Fatal("receipt must only include reports matching the signer")
	}
	if len(session.result.Models) != 2 || session.selected.Signer != b.Signer || !client.client.options.E2EE {
		t.Fatal("wrong routing or defaults")
	}
	if sharedSigner && session.selected.InstanceID != "other" {
		t.Fatal("serving metadata must not change which key the original route selects")
	}
	receipt.Attestations[0].InstanceID = "changed"
	receipt.Attestations[0].Deployment.AppCompose = "changed"
	cachedReceipt, err := client.VerifyResponse(context.Background(), "chat")
	if err != nil || cachedReceipt.Attestations[0].InstanceID == "changed" || cachedReceipt.Attestations[0].Deployment.AppCompose == "changed" || len(cachedReceipt.Attestations) != len(receipt.Attestations) {
		t.Fatal("Direct receipt cache must retain the complete independent evidence snapshot", err)
	}
	if client.client.responses["chat"].request != nil || client.client.responses["chat"].response != nil || client.client.responses["chat"].session != nil {
		t.Fatal("completed Direct verification must release captured bodies and session")
	}
}
func TestDirectSharedSignerDoesNotAttributeInstance(t *testing.T) {
	a, _, priv := attestationFixture(t, Ed25519)
	request := []byte(`{"model":"canonical/model"}`)
	response := []byte(`{"id":"chat"}`)
	text := "canonical/model:" + hashText(request) + ":" + hashText(response)
	sig := CompletionSignature{"provider_tee", text, hex.EncodeToString(ed25519.Sign(priv, []byte(text))), a.Signer}
	items := []VerifiedAttestation{{Signer: a.Signer, InstanceID: "one"}, {Signer: a.Signer, InstanceID: "two"}}
	result, e := VerifyDirectModelResponse("chat", request, response, sig, items)
	if e != nil {
		t.Fatal(e)
	}
	if result.ID != "chat" || result.CompletionID != result.ID {
		t.Fatal("receipt ID alias mismatch")
	}
	var _ VerifiedDirectCompletionResult = result
	if len(result.Attestations) != 2 {
		t.Fatal("ambiguous instance attribution")
	}
}

func TestDirectClientPublicSurface(t *testing.T) {
	client, err := NewDirectInferenceClient(DirectInferenceOptions{InferenceOptions: InferenceOptions{
		ClientOptions: ClientOptions{BaseURL: "https://direct.invalid/v1"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var _ http.RoundTripper = client
	var _ func(context.Context, string) (DirectAttestationVerificationResult, error) = client.Verify
	var _ func(context.Context, string) (VerifiedDirectCompletionResult, error) = client.VerifyResponse
	if client.HTTPClient().Transport != client {
		t.Fatal("HTTP adapter must not expose the Gateway client engine")
	}
	if err := client.HTTPClient().CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatal("Direct adapter must keep redirect refusal")
	}
	for _, method := range []string{"CreateResponse", "CreateMessage", "CreateSystemOne", "CreateSystemOneWithHeaders"} {
		if _, exists := reflect.TypeOf(client).MethodByName(method); exists {
			t.Fatalf("Direct client exposes Gateway-only %s", method)
		}
	}
	for _, result := range []reflect.Type{reflect.TypeFor[DirectAttestationVerificationResult](), reflect.TypeFor[VerifiedDirectCompletionResult]()} {
		for _, field := range []string{"Gateway", "Models", "Attestation"} {
			if _, exists := result.FieldByName(field); exists {
				t.Fatalf("%s exposes unrelated field %s", result.Name(), field)
			}
		}
	}
	for _, endpoint := range []string{"responses", "messages", "systemone"} {
		req, err := http.NewRequest(http.MethodPost, client.BaseURL()+endpoint, strings.NewReader(`{"model":"canonical/model"}`))
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.RoundTrip(req)
		requireCode(t, err, "api.invalid_input")
	}
}
