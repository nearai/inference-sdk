package nearai

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

type directRouteCase struct {
	ohttp, sharedSigner, e2ee, wrongSigner bool
}

func TestDirectReceiptRoute(t *testing.T) {
	for _, e2ee := range []bool{false, true} {
		for name, tc := range map[string]directRouteCase{
			"selected signer":       {},
			"other verified signer": {wrongSigner: true},
			"shared signer":         {sharedSigner: true},
			"OHTTP":                 {ohttp: true},
		} {
			tc.e2ee = e2ee
			t.Run(fmt.Sprintf("%s/E2EE=%t", name, e2ee), func(t *testing.T) { testDirectRoute(t, tc) })
		}
	}
}
func testDirectRoute(t *testing.T, tc directRouteCase) {
	ohttp, sharedSigner := tc.ohttp, tc.sharedSigner
	a, qa, otherKey := attestationFixture(t, Ed25519)
	b, qb, priv := attestationFixture(t, Ed25519)
	a.InstanceID, b.InstanceID = "other", "serving"
	if sharedSigner {
		a.Signer, a.SigningPublicKey = b.Signer, b.SigningPublicKey
		copy(qa.ReportData[:32], qb.ReportData[:32])
	}
	request := json.RawMessage(`{"messages":[],"model":"canonical/model"}`)
	response := []byte(`{"id":"chat","choices":[]}`)
	text := "canonical/model:" + hashText(request) + ":" + hashText(response)
	pub, _, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if e != nil {
		t.Fatal(e)
	}
	pk, _ := pub.MarshalBinary()
	config := append([]byte{1, 0, 32}, pk...)
	config = append(config, 0, 4, 0, 1, 0, 1)
	var fingerprint string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			if r.Header.Get("X-Model-Pub-Key") != b.SigningPublicKey {
				t.Error("Chat must use the serving signer's key")
			}
			w.Write(response)
			return
		}
		if r.URL.Path == "/v1/signature/chat" {
			signingKey, signer := priv, b.Signer
			if tc.wrongSigner {
				signingKey, signer = otherKey, a.Signer
			}
			json.NewEncoder(w).Encode(map[string]any{
				"text": text, "signature": hex.EncodeToString(ed25519.Sign(signingKey, []byte(text))),
				"signing_algo": "ed25519", "signing_address": signer.SigningAddress,
			})
			return
		}
		if r.URL.Query().Get("include_tls_fingerprint") != "true" {
			t.Error("direct reports must request TLS fingerprints")
		}
		n := r.URL.Query().Get("nonce")
		makeReport := func(a Attestation, q QuoteVerificationResult) map[string]any {
			q.ReportData = append([]byte(nil), q.ReportData...)
			nonce, _ := unhex(n)
			copy(q.ReportData[32:], nonce)
			pin := fingerprint
			if a.InstanceID == "other" {
				pin = strings.Repeat("44", 32)
			}
			signer, _ := signingBytes(a.Signer)
			pinBytes, _ := unhex(pin)
			binding := sha256.Sum256(append(signer, pinBytes...))
			copy(q.ReportData[:32], binding[:])
			encoded, _ := json.Marshal(q)
			return map[string]any{
				"model_name":           "canonical/model",
				"tls_cert_fingerprint": pin,
				"request_nonce":        n,
				"signing_algo":         "ed25519",
				"signing_address":      a.Signer.SigningAddress,
				"signing_public_key":   a.SigningPublicKey,
				"intel_quote":          string(encoded),
				"event_log":            a.EventLog,
				"info":                 map[string]any{"instance_id": a.InstanceID, "tcb_info": map[string]any{"app_compose": a.AppCompose}},
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
	fp := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	fingerprint = hex.EncodeToString(fp[:])
	calls := 0
	check := func(context.Context, MeasuredDeployment) error { calls++; return nil }
	client, e := NewDirectInferenceClient(DirectInferenceOptions{
		ClientOptions:     ClientOptions{BaseURL: server.URL + "/v1", HTTPClient: server.Client()},
		E2EE:              tc.e2ee,
		OHTTP:             ohttp,
		ModelVerification: VerificationOptions{QuoteVerifier: fakeQuote, DeploymentVerifier: check},
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
	if preflight.ServingAttestation.InstanceID != "serving" || len(preflight.SPKIFingerprints) != 2 || preflight.VerifiedAt.IsZero() {
		t.Fatal("preflight must retain both verified TLS identities and the serving report")
	}
	cached, err := client.Verify(context.Background(), "canonical/model")
	if err != nil || calls != 2 || !reflect.DeepEqual(cached, preflight) {
		t.Fatal("Direct preflight must reuse the original verified reports and timestamp", err)
	}
	session, err := client.inferenceCore.getSession(context.Background(), "canonical/model")
	if err != nil {
		t.Fatal(err)
	}
	if ohttp {
		err = client.inferenceCore.register("chat", request, response, session, false, client.inferenceCore.responseCacheGeneration())
	} else {
		_, err = client.CreateChatCompletion(context.Background(), request)
	}
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.VerifyResponse(context.Background(), "chat")
	if tc.wrongSigner {
		requireCode(t, err, "signature.signer_mismatch")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if sharedSigner {
		if len(receipt.Attestations) != 2 || receipt.Attestations[0].InstanceID != "other" || receipt.Attestations[1].InstanceID != "serving" {
			t.Fatal("receipt must preserve every report sharing the signer")
		}
	} else if len(receipt.Attestations) != 1 || receipt.Attestations[0].InstanceID != "serving" {
		t.Fatal("receipt must only include reports matching the signer")
	}
	if len(session.direct.Attestations) != 2 || session.selected.Signer != b.Signer || client.inferenceCore.options.E2EE != tc.e2ee {
		t.Fatal("wrong routing or defaults")
	}
	if sharedSigner && session.selectedDirectAttestations[0].InstanceID != "other" {
		t.Fatal("serving metadata must not change which key the original route selects")
	}
	cachedReceipt, err := client.VerifyResponse(context.Background(), "chat")
	if err != nil || !reflect.DeepEqual(cachedReceipt, receipt) {
		t.Fatal("Direct receipt cache must retain the complete verified result", err)
	}
	if client.inferenceCore.responses["chat"].request != nil || client.inferenceCore.responses["chat"].response != nil || client.inferenceCore.responses["chat"].session != nil {
		t.Fatal("completed Direct verification must release captured bodies and session")
	}
}
func TestDirectSharedSignerDoesNotAttributeInstance(t *testing.T) {
	a, _, priv := attestationFixture(t, Ed25519)
	request := []byte(`{"model":"canonical/model"}`)
	response := []byte(`{"id":"chat"}`)
	text := "canonical/model:" + hashText(request) + ":" + hashText(response)
	sig := CompletionSignature{"provider_tee", text, hex.EncodeToString(ed25519.Sign(priv, []byte(text))), a.Signer}
	base := VerifiedModelAttestation{VerifiedAttestationEvidence: VerifiedAttestationEvidence{Signer: a.Signer}}
	items := []VerifiedDirectModelAttestation{{VerifiedModelAttestation: base, InstanceID: "one"}, {VerifiedModelAttestation: base, InstanceID: "two"}}
	result, e := FindDirectModelAttestationsForSignature(items, sig)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(result, items) {
		t.Fatal("ambiguous instance attribution")
	}
	if err := VerifyDirectModelResponse(request, response, sig, result[0]); err != nil {
		t.Fatal(err)
	}
}

func TestDirectHTTPAdapterRejectsUnsupportedEndpoints(t *testing.T) {
	client, err := NewDirectInferenceClient(DirectInferenceOptions{
		ClientOptions: ClientOptions{BaseURL: "https://direct.invalid/v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.HTTPClient().Transport != client {
		t.Fatal("HTTP adapter must use its owning Direct client")
	}
	if err := client.HTTPClient().CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatal("Direct adapter must keep redirect refusal")
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
