//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
)

func TestSystemOne(t *testing.T) {
	model := selectedModels(t, "systemone")[0]
	for _, algo := range []nearai.SigningAlgo{nearai.Ed25519, nearai.ECDSA} {
		t.Run(string(algo), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			client, err := nearai.NewInferenceClient(nearai.InferenceOptions{ClientOptions: nearai.ClientOptions{APIKey: required(t, "NEARAI_API_KEY"), BaseURL: required(t, "NEARAI_BASE_URL")}, SigningAlgo: algo})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			result, err := client.CreateSystemOne(ctx, systemOneRequest(model.ID))
			if err != nil {
				t.Fatal(err)
			}
			var receipt nearai.VerifiedCompletionResult
			if err = retry(ctx, func() error { var e error; receipt, e = client.VerifyResponse(ctx, result.DecisionID); return e }); err != nil {
				t.Fatal(err)
			}
			if receipt.ID != result.DecisionID || receipt.SignatureKind != "gateway" || receipt.Signature.Signer.SigningAlgo != algo || receipt.Attestation == nil || receipt.Attestation.SPKIFingerprint == "" {
				t.Fatal("expected TLS-bound Gateway receipt")
			}
			team := result.Data.Answers["team"].Choice
			if result.Data.Model == "" || result.Data.Usage.InputTokens <= 0 || team == nil || (*team != "billing" && *team != "support") {
				t.Fatal("incomplete decision response")
			}
			for key, kind := range map[string]string{"billing": "noul", "team": "choice", "urgency": "score"} {
				if result.Data.Answers[key].Type != kind {
					t.Fatal("missing answer variant", key)
				}
			}
		})
	}
}

func systemOneRequest(model string) nearai.SystemOneRequest {
	return nearai.SystemOneRequest{
		Model: model, State: map[string]string{"message": "I was charged twice for my subscription. Please help."},
		Questions: map[string]nearai.SystemOneQuestion{
			"billing": {Type: "noul", Instructions: "Is this about billing?"},
			"team":    {Type: "choice", Instructions: "Which team should handle this?", Criteria: map[string]string{"billing": "Payments and subscriptions", "support": "Technical issues"}},
			"urgency": {Type: "score", Instructions: "How urgent is this request?", Criteria: []string{"Routine", "Needs prompt attention", "Critical"}},
		},
	}
}

func TestStandaloneSystemOne(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	base, key := required(t, "NEARAI_BASE_URL"), required(t, "NEARAI_API_KEY")
	client, err := nearai.NewAttestationClient(nearai.ClientOptions{APIKey: key, BaseURL: base})
	if err != nil {
		t.Fatal(err)
	}
	fetched, err := client.FetchGatewayAttestation(ctx, nearai.FetchOptions{SigningAlgo: nearai.Ed25519})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := nearai.VerifyGatewayAttestation(ctx, fetched.Attestation, fetched.ClientBinding, nearai.VerificationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gateway.SPKIFingerprint == "" {
		t.Fatal("missing attested TLS binding")
	}
	transport, err := nearai.NewPinnedTransport(nil, gateway.SPKIFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	body, err := json.Marshal(systemOneRequest(selectedModels(t, "systemone")[0].ID))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(base, "/")+"/systemone", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set(nearai.NoAliasingHeader, "true")
	res, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	id := res.Header.Get("X-Generation-Id")
	if id == "" {
		res.Body.Close()
		t.Fatal("missing decision ID")
	}
	raw := readResponse(t, res)
	var signature nearai.CompletionSignature
	if err = retry(ctx, func() error {
		var e error
		signature, e = client.FetchCompletionSignature(ctx, id, nearai.Ed25519)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if signature.Kind != "gateway" {
		t.Fatal("expected Gateway receipt")
	}
	if err = nearai.VerifyGatewayResponse(body, raw, signature, gateway); err != nil {
		t.Fatal(err)
	}
	if nearai.VerifyGatewayResponse(append(bytes.Clone(body), ' '), raw, signature, gateway) == nil {
		t.Fatal("changed request accepted")
	}
	if nearai.VerifyGatewayResponse(body, append(bytes.Clone(raw), ' '), signature, gateway) == nil {
		t.Fatal("changed response accepted")
	}
}
