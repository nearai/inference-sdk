package nearai

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

func TestDirectOHTTPSelectsServingSigner(t *testing.T) {
	a, qa, _ := attestationFixture(t, Ed25519)
	b, qb, priv := attestationFixture(t, Ed25519)
	pub, _, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if e != nil {
		t.Fatal(e)
	}
	pk, _ := pub.MarshalBinary()
	config := append([]byte{1, 0, 32}, pk...)
	config = append(config, 0, 4, 0, 1, 0, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("include_tls_fingerprint") != "false" {
			t.Error("direct TLS must be disabled")
		}
		n := r.URL.Query().Get("nonce")
		makeReport := func(a Attestation, q QuoteVerificationResult) map[string]any {
			q.ReportData = append([]byte(nil), q.ReportData...)
			nonce, _ := unhex(n)
			copy(q.ReportData[32:], nonce)
			encoded, _ := json.Marshal(q)
			return map[string]any{"model_name": "canonical/model", "request_nonce": n, "signing_algo": "ed25519", "signing_address": a.Signer.SigningAddress, "signing_public_key": a.SigningPublicKey, "intel_quote": string(encoded), "event_log": a.EventLog, "info": map[string]any{"tcb_info": map[string]any{"app_compose": a.AppCompose}}}
		}
		first, serving := makeReport(a, qa), makeReport(b, qb)
		root := map[string]any{}
		for k, v := range serving {
			root[k] = v
		}
		root["all_attestations"] = []any{first, serving}
		root["ohttp_attestation"] = OHTTPAttestation{Ed25519, b.Signer.SigningAddress, hex.EncodeToString(config), hex.EncodeToString(ed25519.Sign(priv, config))}
		json.NewEncoder(w).Encode(root)
	}))
	defer server.Close()
	client, e := NewDirectInferenceClient(DirectInferenceOptions{InferenceOptions: InferenceOptions{ClientOptions: ClientOptions{BaseURL: server.URL + "/v1"}, OHTTP: true, ModelVerification: VerificationOptions{QuoteVerifier: fakeQuote}}})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	session, e := client.getSession(context.Background(), "canonical/model")
	if e != nil {
		t.Fatal(e)
	}
	if len(session.result.Models) != 2 || session.selected.Signer != b.Signer || !client.options.E2EE {
		t.Fatal("wrong routing or defaults")
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
	if result.Attestation != nil || len(result.Attestations) != 2 {
		t.Fatal("ambiguous instance attribution")
	}
}
