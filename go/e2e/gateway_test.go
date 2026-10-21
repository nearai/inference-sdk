//go:build e2e

// Live tests opt in with -tags=e2e and never substitute quote/GPU verifiers.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
)

type liveModel struct{ ID, Provider, Endpoint string }

func required(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required for live E2E tests", name)
	}
	return value
}
func selectedModels(t *testing.T, endpoint string) []liveModel {
	t.Helper()
	var all []liveModel
	if err := json.Unmarshal([]byte(required(t, "NEARAI_E2E_MODELS")), &all); err != nil {
		t.Fatal(err)
	}
	selected := make([]liveModel, 0, len(all))
	for _, m := range all {
		if m.Endpoint == endpoint {
			selected = append(selected, m)
		}
	}
	if len(selected) == 0 {
		t.Fatalf("expected representative %s models", endpoint)
	}
	for _, m := range selected {
		if m.ID == "" || (m.Provider != "near" && m.Provider != "chutes" && m.Provider != "external") {
			t.Fatalf("invalid selected model: %v", m)
		}
	}
	return selected
}
func models(t *testing.T, encryption bool) []liveModel {
	t.Helper()
	all := selectedModels(t, "chat")
	if encryption {
		for _, m := range all {
			if m.Provider == "near" {
				return []liveModel{m}
			}
		}
		t.Fatal("expected a NEAR model for encryption coverage")
	}
	return all
}

func TestSelectedModels(t *testing.T) {
	t.Setenv("NEARAI_E2E_MODELS", `[
		{"id":"near/chat","provider":"near","endpoint":"chat"},
		{"id":"typesafe/decision","provider":"external","endpoint":"systemone"}
	]`)
	for endpoint, id := range map[string]string{"chat": "near/chat", "systemone": "typesafe/decision"} {
		selected := selectedModels(t, endpoint)
		if len(selected) != 1 || selected[0].ID != id {
			t.Fatalf("%s selected wrong models: %v", endpoint, selected)
		}
	}
}
func chatRequest(ctx context.Context, base, key string, m liveModel, stream bool) (*http.Request, []byte, error) {
	body, err := json.Marshal(map[string]any{
		"model":                 m.ID,
		"messages":              []map[string]string{{"role": "user", "content": "Reply with the single word OK."}},
		"max_completion_tokens": 1024,
		"stream":                stream,
	})
	if err != nil {
		return nil, nil, err
	}
	r, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(base, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set(nearai.NoAliasingHeader, "true")
	return r, body, nil
}
func completionID(t *testing.T, raw []byte, stream bool) string {
	t.Helper()
	type choice struct {
		Message      struct{ Content string }
		Delta        struct{ Content string }
		FinishReason *string `json:"finish_reason"`
	}
	type completion struct {
		ID      string
		Choices []choice
		Error   any
	}
	parse := func(data []byte) completion {
		var c completion
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		if c.Error != nil {
			t.Fatal("Chat returned an error")
		}
		if c.ID == "" {
			t.Fatal("missing completion ID")
		}
		return c
	}
	if !stream {
		c := parse(raw)
		if len(c.Choices) == 0 || strings.TrimSpace(c.Choices[0].Message.Content) == "" || c.Choices[0].FinishReason == nil || *c.Choices[0].FinishReason != "stop" {
			t.Fatal("expected nonempty complete JSON answer")
		}
		return c.ID
	}
	id, text, finish := "", "", ""
	done := false
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r", ""), "\n") {
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(line[5:])
		if data == "" {
			continue
		}
		if data == "[DONE]" {
			done = true
			continue
		}
		if done {
			t.Fatal("data after [DONE]")
		}
		c := parse([]byte(data))
		if id != "" && id != c.ID {
			t.Fatal("conflicting completion IDs")
		}
		id = c.ID
		for _, choice := range c.Choices {
			text += choice.Delta.Content
			if choice.FinishReason != nil {
				finish = *choice.FinishReason
			}
		}
	}
	if !done || id == "" || strings.TrimSpace(text) == "" || finish != "stop" {
		t.Fatal("expected nonempty complete SSE answer")
	}
	return id
}
func retry(ctx context.Context, check func() error) error {
	for _, delay := range []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 0} {
		err := check()
		if err == nil {
			return nil
		}
		var sdk *nearai.Error
		if !errors.As(err, &sdk) || (!sdk.Retryable && sdk.Code != "api.completion_signature_unavailable") || delay == 0 {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}
func assertEvidence(t *testing.T, m liveModel, reports []nearai.VerifiedAttestation) {
	t.Helper()
	if m.Provider != "near" {
		if len(reports) != 0 {
			t.Fatal("expected Gateway-only verification")
		}
		return
	}
	if len(reports) == 0 {
		t.Fatal("expected NEAR model evidence")
	}
	for _, a := range reports {
		if a.GPUEvidence != "verified" || a.SigningPublicKey == "" {
			t.Fatal("expected verified GPU evidence and model public key")
		}
	}
}
func readResponse(t *testing.T, res *http.Response) []byte {
	t.Helper()
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("Chat HTTP %d", res.StatusCode)
	}
	// Consume actual EOF, including after SSE [DONE] and OHTTP final authentication.
	raw, err := io.ReadAll(io.LimitReader(res.Body, (64<<20)+1))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 64<<20 {
		t.Fatal("Chat body too large")
	}
	return raw
}
func TestStandaloneEd25519(t *testing.T) { standalone(t, nearai.Ed25519) }
func TestStandaloneECDSA(t *testing.T)   { standalone(t, nearai.ECDSA) }
func standalone(t *testing.T, algo nearai.SigningAlgo) {
	base, key := required(t, "NEARAI_BASE_URL"), required(t, "NEARAI_API_KEY")
	for _, m := range models(t, false) {
		t.Run(m.Provider+"/"+m.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()
			api, err := nearai.NewAttestationClient(nearai.ClientOptions{APIKey: key, BaseURL: base})
			if err != nil {
				t.Fatal(err)
			}
			fetched, err := api.FetchGatewayAttestation(ctx, nearai.FetchOptions{SigningAlgo: algo})
			if err != nil {
				t.Fatal(err)
			}
			gateway, err := nearai.VerifyGatewayAttestation(ctx, fetched.Attestation, fetched.ClientBinding, nearai.VerificationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if gateway.SPKIFingerprint == "" {
				t.Fatal("missing attested Gateway TLS binding")
			}
			transport, err := nearai.NewPinnedTransport(nil, gateway.SPKIFingerprint)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{
				Transport:     transport,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
			api, err = nearai.NewAttestationClient(nearai.ClientOptions{
				APIKey:     key,
				BaseURL:    base,
				HTTPClient: client,
			})
			if err != nil {
				t.Fatal(err)
			}

			var reports []nearai.VerifiedAttestation
			if m.Provider == "near" {
				fetched, err := api.FetchModelAttestations(ctx, m.ID, nearai.FetchOptions{SigningAlgo: algo})
				if err != nil {
					t.Fatal(err)
				}
				for _, a := range fetched.Attestations {
					v, err := nearai.VerifyModelAttestation(ctx, a, fetched.ClientBinding, nearai.VerificationOptions{})
					if err != nil {
						t.Fatal(err)
					}
					reports = append(reports, v)
				}
			}
			assertEvidence(t, m, reports)
			for _, stream := range []bool{false, true} {
				if stream && m.Provider == "chutes" {
					continue
				}
				r, request, err := chatRequest(ctx, base, key, m, stream)
				if err != nil {
					t.Fatal(err)
				}
				res, err := sendChatWithRetry(ctx, client, r)
				if err != nil {
					t.Fatal(err)
				}
				raw := readResponse(t, res)
				id := completionID(t, raw, stream)
				var sig nearai.CompletionSignature
				if err = retry(ctx, func() error { var e error; sig, e = api.FetchCompletionSignature(ctx, id, algo); return e }); err != nil {
					t.Fatal(err)
				}
				if sig.Signer.SigningAlgo != algo {
					t.Fatal("wrong receipt algorithm")
				}
				if m.Provider != "near" && sig.Kind != "gateway" {
					t.Fatal("expected Gateway receipt")
				}
				verify := func(body []byte) error {
					if sig.Kind == "gateway" {
						return nearai.VerifyGatewayResponse(request, body, sig, gateway)
					}
					signer, e := nearai.FindModelAttestationForSignature(reports, sig)
					if e != nil {
						return e
					}
					return nearai.VerifyModelResponse(request, body, sig, signer)
				}
				if err = verify(raw); err != nil {
					t.Fatal(err)
				}
				if verify(append(append([]byte(nil), raw...), ' ')) == nil {
					t.Fatal("altered response accepted")
				}
				t.Logf("%s stream=%t: verified %s receipt", algo, stream, sig.Kind)
			}
		})
	}
}
func TestIntegratedPlaintext(t *testing.T)   { integrated(t, false, nearai.Ed25519, false) }
func TestIntegratedEd25519E2EE(t *testing.T) { integrated(t, true, nearai.Ed25519, false) }
func TestIntegratedECDSAE2EE(t *testing.T)   { integrated(t, true, nearai.ECDSA, false) }
func TestIntegratedOHTTPE2EE(t *testing.T)   { integrated(t, true, nearai.Ed25519, true) }
func integrated(t *testing.T, e2ee bool, algo nearai.SigningAlgo, ohttp bool) {
	base, key := required(t, "NEARAI_BASE_URL"), required(t, "NEARAI_API_KEY")
	for _, m := range models(t, e2ee || ohttp) {
		t.Run(m.Provider+"/"+m.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()
			client, err := nearai.NewInferenceClient(nearai.InferenceOptions{
				ClientOptions: nearai.ClientOptions{APIKey: key, BaseURL: base},
				SigningAlgo:   algo,
				E2EE:          e2ee,
				OHTTP:         ohttp,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var preflight nearai.AttestationVerificationResult
			if !e2ee {
				preflight, err = client.Verify(ctx, m.ID)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, stream := range []bool{false, true} {
				if stream && m.Provider == "chutes" {
					continue
				}
				r, _, err := chatRequest(ctx, base, key, m, stream)
				if err != nil {
					t.Fatal(err)
				}
				res, err := sendChatWithRetry(ctx, client.HTTPClient(), r)
				if err != nil {
					t.Fatal(err)
				}
				id := completionID(t, readResponse(t, res), stream)
				var receipt nearai.VerifiedCompletionResult
				if err = retry(ctx, func() error { var e error; receipt, e = client.VerifyResponse(ctx, id); return e }); err != nil {
					t.Fatal(err)
				}
				if receipt.Signature.Signer.SigningAlgo != algo {
					t.Fatal("wrong receipt algorithm")
				}
				if m.Provider != "near" && receipt.SignatureKind != "gateway" {
					t.Fatal("expected Gateway receipt")
				}
				cached, err := client.VerifyResponse(ctx, id)
				if err != nil || cached.Signature.Signature != receipt.Signature.Signature {
					t.Fatalf("cached receipt: %v", err)
				}
				verified, err := client.Verify(ctx, m.ID)
				if err != nil {
					t.Fatal(err)
				}
				if verified.Gateway == nil || verified.Gateway.SPKIFingerprint == "" {
					t.Fatal("missing attested Gateway TLS binding")
				}
				assertEvidence(t, m, verified.Models)
				if !preflight.VerifiedAt.IsZero() && !preflight.VerifiedAt.Equal(verified.VerifiedAt) {
					t.Fatal("preflight was not cached")
				}
				again, err := client.Verify(ctx, m.ID)
				if err != nil || !again.VerifiedAt.Equal(verified.VerifiedAt) {
					t.Fatalf("cached preflight: %v", err)
				}
				t.Logf("%s e2ee=%t ohttp=%t stream=%t: verified %s receipt", algo, e2ee, ohttp, stream, receipt.SignatureKind)
			}
		})
	}
}
