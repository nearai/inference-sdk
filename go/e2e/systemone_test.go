//go:build e2e

package e2e

import (
	"context"
	nearai "github.com/nearai/inference-sdk/go"
	"testing"
	"time"
)

func TestSystemOne(t *testing.T) {
	for _, algo := range []nearai.SigningAlgo{nearai.Ed25519, nearai.ECDSA} {
		t.Run(string(algo), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			client, err := nearai.NewInferenceClient(nearai.InferenceOptions{ClientOptions: nearai.ClientOptions{APIKey: required(t, "NEARAI_API_KEY"), BaseURL: required(t, "NEARAI_BASE_URL")}, SigningAlgo: algo})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			result, err := client.CreateSystemOne(ctx, nearai.SystemOneRequest{
				Model: required(t, "NEARAI_E2E_SYSTEMONE_MODEL"), State: map[string]string{"message": "I was charged twice for my subscription. Please help."},
				Questions: map[string]nearai.SystemOneQuestion{
					"billing": {Type: "noul", Instructions: "Is this about billing?"},
					"team":    {Type: "choice", Instructions: "Which team should handle this?", Criteria: map[string]string{"billing": "Payments", "support": "Technical help"}},
					"urgency": {Type: "score", Instructions: "How urgent is this request?", Criteria: []string{"Routine", "Prompt attention", "Critical"}},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			var receipt nearai.VerifiedCompletionResult
			if err = retry(ctx, func() error { var e error; receipt, e = client.VerifyResponse(ctx, result.DecisionID); return e }); err != nil {
				t.Fatal(err)
			}
			if receipt.SignatureKind != "gateway" || receipt.Signature.Signer.SigningAlgo != algo || receipt.Attestation == nil || receipt.Attestation.SPKIFingerprint == "" {
				t.Fatal("expected TLS-bound Gateway receipt")
			}
			for key, kind := range map[string]string{"billing": "noul", "team": "choice", "urgency": "score"} {
				if result.Data.Answers[key].Type != kind {
					t.Fatal("missing answer variant", key)
				}
			}
		})
	}
}
