package nearai

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
)

func TestRejectedGatewayDoesNotFetchModelReports(t *testing.T) {
	fixture := newFakeCloud(t)
	fixture.tee = true
	client, _ := fakeClient(t, fixture, func(options *InferenceOptions) {
		options.GatewayVerification.QuoteVerifier = func(context.Context, string) (QuoteVerificationResult, error) {
			return QuoteVerificationResult{}, failure("policy.debug_enabled", nil)
		}
	})
	if _, err := client.Verify(context.Background(), "canonical/model"); err == nil {
		t.Fatal("expected Gateway verification rejection")
	}
	if fixture.attestations.Load() != 1 || fixture.chats.Load() != 0 {
		t.Fatal("rejected Gateway was used for further requests")
	}
}

func TestGatewayOHTTPVerificationPrecedesAuthenticatedRequests(t *testing.T) {
	pub, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	key, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	validConfig := append([]byte{1, 0, 32}, key...)
	validConfig = append(validConfig, 0, 4, 0, 1, 0, 1)
	for _, tc := range []struct{ name, code string }{
		{"missing", "ohttp.attestation_required"},
		{"invalid_signature", "ohttp.signature_invalid"},
		{"invalid_config", "ohttp.key_config_invalid"},
		{"valid", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newFakeCloud(t)
			fixture.tee = true
			if tc.name != "missing" {
				config := validConfig
				if tc.name == "invalid_config" {
					config = []byte("invalid")
				}
				fixture.ohttp = &OHTTPAttestation{
					SigningAlgo: Ed25519,
					SigningKey:  fixture.a.Signer.SigningAddress,
					KeyConfig:   hex.EncodeToString(config),
					Signature:   hex.EncodeToString(ed25519.Sign(fixture.priv, config)),
				}
				if tc.name == "invalid_signature" {
					fixture.ohttp.Signature = strings.Repeat("00", ed25519.SignatureSize)
				}
			}
			client, _ := fakeClient(t, fixture, func(options *InferenceOptions) {
				options.OHTTP = true
			})
			session, err := client.getSession(context.Background(), "canonical/model")
			if tc.code != "" {
				requireCode(t, err, tc.code)
				if fixture.metadata.Load() != 0 || fixture.attestations.Load() != 1 {
					t.Fatalf("invalid OHTTP evidence allowed authenticated preflight: metadata=%d reports=%d", fixture.metadata.Load(), fixture.attestations.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := session.transport.(*ohttpTransport); !ok {
				t.Fatal("valid OHTTP configuration was not installed")
			}
			if fixture.metadata.Load() != 1 || fixture.attestations.Load() != 2 || len(session.models) != 1 {
				t.Fatal("valid OHTTP evidence did not allow authenticated model verification")
			}
		})
	}
}

func TestClientDoesNotReplayAfterConnectionFailure(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, header := range []string{"Idempotency-Key", "X-Idempotency-Key"} {
			t.Run(fmt.Sprintf("encrypted=%t/%s", encrypted, header), func(t *testing.T) {
				transport := &http.Transport{}
				t.Cleanup(transport.CloseIdleConnections)
				f := newFakeCloud(t)
				f.tee, f.encrypt, f.dropChatAt = encrypted, encrypted, 2
				client, _ := fakeClient(t, f, func(o *InferenceOptions) {
					o.E2EE = encrypted
					o.HTTPClient = &http.Client{Transport: transport}
					o.Headers = http.Header{header: {"completion-key"}}
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := client.CreateChatCompletion(ctx, chatRequest()); err != nil {
					t.Fatal(err)
				}

				var reused atomic.Bool
				ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
					GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) },
				})
				_, err := client.CreateChatCompletion(ctx, chatRequest())

				if !reused.Load() {
					t.Fatal("did not exercise a reused connection")
				}
				if err == nil {
					t.Fatal("connection failure was not propagated")
				}
				if f.chats.Load() != 2 {
					t.Fatalf("completion was replayed: %d requests, want warmup + one failed request", f.chats.Load())
				}
			})
		}
	}
}

func TestClientPreflightAndSignature(t *testing.T) {
	for _, tee := range []bool{false, true} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("tee=%t/stream=%t", tee, stream), func(t *testing.T) {
				f := newFakeCloud(t)
				f.tee = tee
				f.stream = stream
				c, _ := fakeClient(t, f, nil)
				first, e := c.Verify(context.Background(), "canonical/model")
				if e != nil {
					t.Fatal(e)
				}
				second, e := c.Verify(context.Background(), "canonical/model")
				if e != nil || !first.VerifiedAt.Equal(second.VerifiedAt) {
					t.Fatal("cache not reused")
				}
				body, _ := json.Marshal(chatRequest())
				req, _ := http.NewRequest("POST", c.BaseURL()+"chat/completions", bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer wrong")
				req.Header.Set("X-Signing-Algo", "ecdsa")
				req.Header.Set("X-Client-Pub-Key", "stale")
				res, e := c.HTTPClient().Do(req)
				if e != nil {
					t.Fatal(e)
				}
				_, e = io.ReadAll(res.Body)
				res.Body.Close()
				if e != nil {
					t.Fatal(e)
				}
				verified, e := c.VerifyResponse(context.Background(), "chat-1")
				if e != nil {
					t.Fatal(e)
				}
				if verified.ID != "chat-1" || verified.CompletionID != verified.ID {
					t.Fatal("receipt ID alias mismatch")
				}
				want := "gateway"
				if tee {
					want = "provider_tee"
				}
				if verified.SignatureKind != want {
					t.Fatal(verified)
				}
				expected := int32(1)
				if tee {
					expected = 2
				}
				if f.attestations.Load() != expected {
					t.Fatal("preflight cache missed")
				}
			})
		}
	}
}
func TestVerificationReleasesCapturedBodies(t *testing.T) {
	for _, tc := range []struct {
		name                string
		tee, stream, tamper bool
	}{
		{name: "gateway"},
		{name: "model-stream", tee: true, stream: true},
		{name: "invalid-signature", tamper: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeCloud(t)
			f.tee, f.stream, f.tamper = tc.tee, tc.stream, tc.tamper
			c, _ := fakeClient(t, f, nil)
			body, _ := json.Marshal(chatRequest())
			req, _ := http.NewRequest("POST", c.BaseURL()+"chat/completions", bytes.NewReader(body))
			res, err := c.HTTPClient().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			record := c.responses["chat-1"]
			expires := record.expires
			c.mu.Unlock()
			first, firstErr := c.VerifyResponse(context.Background(), "chat-1")
			if tc.tamper {
				requireCode(t, firstErr, "signature.payload_mismatch")
			} else if firstErr != nil {
				t.Fatal(firstErr)
			}
			second, secondErr := c.VerifyResponse(context.Background(), "chat-1")
			if secondErr != firstErr || !reflect.DeepEqual(first, second) || f.signatureCalls.Load() != 1 {
				t.Fatal("terminal verification result was not reused")
			}
			c.mu.Lock()
			retained := c.responses["chat-1"]
			released := retained == record && record.request == nil && record.response == nil && record.session == nil
			unchangedExpiry := record.expires.Equal(expires)
			c.prune(expires)
			c.mu.Unlock()
			if !released || !unchangedExpiry {
				t.Fatal("terminal record retained captured bodies or changed its lifetime")
			}
			_, err = c.VerifyResponse(context.Background(), "chat-1")
			requireCode(t, err, "api.completion_not_found")
		})
	}
}

func TestClearResponseCachePreservesSession(t *testing.T) {
	for _, tee := range []bool{false, true} {
		t.Run(fmt.Sprintf("tee=%t", tee), func(t *testing.T) {
			f := newFakeCloud(t)
			f.tee = tee
			c, _ := fakeClient(t, f, nil)
			ctx := context.Background()
			if _, err := c.CreateChatCompletion(ctx, chatRequest()); err != nil {
				t.Fatal(err)
			}
			if _, err := c.VerifyResponse(ctx, "chat-1"); err != nil {
				t.Fatal(err)
			}
			attestations := f.attestations.Load()
			c.ClearResponseCache()
			c.ClearResponseCache()
			_, err := c.VerifyResponse(ctx, "chat-1")
			requireCode(t, err, "api.completion_not_found")
			if _, err := c.CreateChatCompletion(ctx, chatRequest()); err != nil {
				t.Fatal(err)
			}
			if _, err := c.VerifyResponse(ctx, "chat-2"); err != nil {
				t.Fatal(err)
			}
			if f.attestations.Load() != attestations {
				t.Fatal("clearing responses discarded the attestation session")
			}
		})
	}
}

func TestClearResponseCacheDuringStream(t *testing.T) {
	for _, endpoint := range []string{"chat/completions", "responses"} {
		t.Run(endpoint, func(t *testing.T) {
			var c *InferenceClient
			var request any
			id := "chat-1"
			if endpoint == "responses" {
				c, _ = responsesClient(t, true, nil)
				request, id = responseInput(true), "resp_fixture"
			} else {
				f := newFakeCloud(t)
				f.stream = true
				c, _ = fakeClient(t, f, nil)
				request = chatRequest()
			}
			body, _ := json.Marshal(request)
			req, _ := http.NewRequest("POST", c.BaseURL()+endpoint, bytes.NewReader(body))
			response, err := c.HTTPClient().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if _, err := io.ReadFull(response.Body, make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			c.ClearResponseCache()
			if _, err := io.Copy(io.Discard, response.Body); err != nil {
				t.Fatal(err)
			}
			_, err = c.VerifyResponse(context.Background(), id)
			requireCode(t, err, "api.completion_not_found")
		})
	}
}

func TestClientCompressedResponses(t *testing.T) {
	for _, encoding := range []string{"gzip", "br"} {
		for _, stream := range []bool{false, true} {
			t.Run(encoding+"/stream="+fmt.Sprint(stream), func(t *testing.T) {
				f := newFakeCloud(t)
				f.encoding, f.stream = encoding, stream
				c, _ := fakeClient(t, f, nil)
				body, _ := json.Marshal(chatRequest())
				req, _ := http.NewRequest("POST", c.BaseURL()+"chat/completions", bytes.NewReader(body))
				res, err := c.HTTPClient().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				if _, err = io.ReadAll(res.Body); err != nil {
					t.Fatal(err)
				}
				if res.Header.Get("Content-Encoding") != "" || res.Header.Get("Content-Length") != "" {
					t.Fatal("decoded response retained compressed headers")
				}
				if _, err = c.VerifyResponse(context.Background(), "chat-1"); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestGatewaySharedSignerReportsSurviveResponseAndCache(t *testing.T) {
	for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
		for _, encrypted := range []bool{false, true} {
			for _, streaming := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/encrypted=%t/streaming=%t", algo, encrypted, streaming), func(t *testing.T) {
					f := newFakeCloud(t)
					if algo == ECDSA {
						f.useECDSA()
					}
					f.encrypt, f.stream = encrypted, streaming
					f.onlyLastModelKey = encrypted
					f.tee, f.sharedModel, f.extraModel = true, true, true
					f.q.AdvisoryIDs = []string{"original"}
					var deployments []string
					client, _ := fakeClient(t, f, func(o *InferenceOptions) {
						o.SigningAlgo, o.E2EE = algo, encrypted
						o.DeploymentPolicy = func(_ context.Context, _ string, deployment MeasuredDeployment) error {
							deployments = append(deployments, deployment.AppCompose)
							return nil
						}
					})
					ctx := context.Background()
					before, err := client.Verify(ctx, "canonical/model")
					if err != nil {
						t.Fatal(err)
					}
					if len(before.Models) != 3 || len(deployments) != 3 || deployments[0] == deployments[2] || before.Models[0].Signer == before.Models[1].Signer {
						t.Fatalf("expected three verified reports with two keys and distinct deployments: %#v %v", before.Models, deployments)
					}
					expected := []VerifiedAttestation{before.Models[0], before.Models[2]}
					selected := before.Models[0]
					if encrypted {
						selected = before.Models[2]
					}
					input := chatRequest()
					input["stream"] = streaming
					body, _ := json.Marshal(input)
					request, _ := http.NewRequestWithContext(ctx, "POST", client.BaseURL()+"chat/completions", bytes.NewReader(body))
					response, err := client.HTTPClient().Do(request)
					if err != nil {
						t.Fatal(err)
					}
					visible, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil || !bytes.Contains(visible, []byte("answer")) {
						t.Fatalf("plaintext response = %s, error = %v", visible, err)
					}
					// Expire the session without sleeping, then fetch new evidence before verifying
					// the receipt. It must keep the complete signer group from the request snapshot.
					client.mu.Lock()
					client.sessions["canonical/model"].expires = time.Time{}
					client.mu.Unlock()
					refreshed, err := client.Verify(ctx, "canonical/model")
					if err != nil {
						t.Fatal(err)
					}
					if reflect.DeepEqual(refreshed.Models, before.Models) || f.modelReports.Load() != 2 {
						t.Fatal("fixture did not refresh the model evidence")
					}
					first, err := client.VerifyResponse(ctx, "chat-1")
					if err != nil {
						t.Fatal(err)
					}
					if len(first.Attestations) != 2 || first.Attestations[0].InstanceID != "instance-0" || first.Attestations[1].InstanceID != "instance-1" || first.Attestation == nil {
						t.Fatalf("response lost shared-signer reports: %#v", first)
					}
					if !reflect.DeepEqual(first.Attestations, expected) || !reflect.DeepEqual(*first.Attestation, selected) {
						t.Fatal("response did not retain the preflight evidence and compatibility representative")
					}
					cached, err := client.VerifyResponse(ctx, "chat-1")
					if err != nil {
						t.Fatal(err)
					}
					after, err := client.Verify(ctx, "canonical/model")
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(cached.Attestations, expected) || !reflect.DeepEqual(after.Models, refreshed.Models) || !reflect.DeepEqual(*cached.Attestation, selected) {
						t.Fatal("cached receipts and current sessions must retain their own preflight evidence")
					}
					if f.attestations.Load() != 4 || f.signatureCalls.Load() != 1 || len(deployments) != 6 {
						t.Fatal("cached verification refetched evidence or reran policy")
					}
				})
			}
		}
	}
}

func TestGatewayStreamReceiptKeepsGatewayEvidenceWithAttestedModels(t *testing.T) {
	f := newFakeCloud(t)
	f.tee, f.sharedModel, f.stream, f.gatewayReceipt = true, true, true, true
	client, _ := fakeClient(t, f, nil)
	ctx := context.Background()
	preflight, err := client.Verify(ctx, "canonical/model")
	if err != nil || len(preflight.Models) != 2 {
		t.Fatalf("model preflight: %#v %v", preflight, err)
	}
	request := chatRequest()
	request["stream"] = true
	body, _ := json.Marshal(request)
	req, _ := http.NewRequestWithContext(ctx, "POST", client.BaseURL()+"chat/completions", bytes.NewReader(body))
	response, err := client.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.VerifyResponse(ctx, "chat-1")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.SignatureKind != "gateway" || len(receipt.Attestations) != 0 || !reflect.DeepEqual(receipt.Attestation, preflight.Gateway) {
		t.Fatalf("gateway receipt did not retain gateway-only evidence: %#v", receipt)
	}
}

func TestGatewayRejectsUnacceptedSharedSignerReportBeforeChat(t *testing.T) {
	for _, name := range []string{"policy", "evidence"} {
		t.Run(name, func(t *testing.T) {
			f := newFakeCloud(t)
			f.tee, f.sharedModel = true, true
			f.badSharedModel = name == "evidence"
			client, _ := fakeClient(t, f, func(o *InferenceOptions) {
				if name == "policy" {
					o.DeploymentPolicy = func(_ context.Context, _ string, deployment MeasuredDeployment) error {
						if deployment.AppCompose != f.a.AppCompose {
							return failure("test.second_deployment_rejected", nil)
						}
						return nil
					}
				}
			})
			_, err := client.CreateChatCompletion(context.Background(), chatRequest())
			if name == "evidence" {
				requireCode(t, err, "policy.debug_enabled")
			} else {
				requireCode(t, err, "provenance.verification_failed")
			}
			if f.chats.Load() != 0 {
				t.Fatal("sent Chat before every shared-signer deployment was accepted")
			}
		})
	}
}

func TestGatewayReceiptRejectsDifferentPreflightVerifiedKey(t *testing.T) {
	f := newFakeCloud(t)
	f.tee, f.extraModel = true, true
	client, _ := fakeClient(t, f, nil)
	ctx := context.Background()
	verified, err := client.Verify(ctx, "canonical/model")
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Models) != 2 || verified.Models[0].Signer == f.a.Signer || verified.Models[1].Signer != f.a.Signer {
		t.Fatal("fixture must select a key different from the response signer")
	}
	if _, err = client.CreateChatCompletion(ctx, chatRequest()); err != nil {
		t.Fatal(err)
	}
	_, err = client.VerifyResponse(ctx, "chat-1")
	requireCode(t, err, "signature.signer_mismatch")
}

func TestClientDeploymentPoliciesReceiveManagerEvidence(t *testing.T) {
	f := newFakeCloud(t)
	f.tee = true
	fixture := loadManagerFixture(t)
	f.a.ComposeManagerAttestation = &ComposeManagerAttestation{Actions: fixture.Actions, ActionsHash: fixture.ActionsHash, EventLog: f.a.EventLog}
	var calls []string
	check := func(name string, deployment MeasuredDeployment) {
		t.Helper()
		if deployment.ComposeManager == nil || !reflect.DeepEqual(deployment.ComposeManager.Actions, fixture.Actions) {
			t.Error("callback did not receive authenticated manager actions")
		}
		calls = append(calls, name)
	}
	client, _ := fakeClient(t, f, func(opts *InferenceOptions) {
		opts.ModelVerification.DeploymentVerifier = func(_ context.Context, deployment MeasuredDeployment) error {
			check("verifier", deployment)
			return nil
		}
		opts.DeploymentPolicy = func(_ context.Context, model string, deployment MeasuredDeployment) error {
			if model != "canonical/model" {
				t.Error("wrong policy model")
			}
			check("policy", deployment)
			return nil
		}
	})
	result, err := client.Verify(context.Background(), "canonical/model")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"verifier", "policy"}) || result.Models[0].DeploymentProvenance != "verified" {
		t.Fatal("deployment policy order or result changed", calls)
	}
	if _, err := client.CreateChatCompletion(context.Background(), chatRequest()); err != nil {
		t.Fatal(err)
	}
	receipt, err := client.VerifyResponse(context.Background(), "chat-1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(receipt.Attestations, result.Models) || !reflect.DeepEqual(receipt.Attestation, &result.Models[0]) {
		t.Fatal("receipt did not retain the verified manager evidence")
	}
}

func TestClientRejectsTamperingAndUnsupportedPrivacy(t *testing.T) {
	t.Run("tampered reply", func(t *testing.T) {
		f := newFakeCloud(t)
		f.tamper = true
		c, _ := fakeClient(t, f, nil)
		if _, e := c.CreateChatCompletion(context.Background(), chatRequest()); e != nil {
			t.Fatal(e)
		}
		_, e := c.VerifyResponse(context.Background(), "chat-1")
		requireCode(t, e, "signature.payload_mismatch")
	})
	for _, name := range []string{"E2EE", "model policy", "invalid second model", "empty model reports"} {
		t.Run(name, func(t *testing.T) {
			f := newFakeCloud(t)
			if name == "invalid second model" {
				f.tee = true
				f.badModel = true
			}
			if name == "empty model reports" {
				f.tee, f.emptyModels = true, true
			}
			c, _ := fakeClient(t, f, func(o *InferenceOptions) {
				if name == "E2EE" {
					o.E2EE = true
				}
				if name == "model policy" {
					o.ModelVerification.Policy.RequireGPUEvidence = true
				}
			})
			_, e := c.CreateChatCompletion(context.Background(), chatRequest())
			if name == "empty model reports" {
				requireCode(t, e, "policy.model_attestation_required")
			}
			if e == nil || f.chats.Load() != 0 {
				t.Fatalf("privacy admission: %v chats=%d", e, f.chats.Load())
			}
		})
	}
}
func TestSharedVerificationCancellation(t *testing.T) {
	f := newFakeCloud(t)
	release := make(chan struct{})
	f.slow = release
	c, _ := fakeClient(t, f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, e := c.Verify(ctx, "canonical/model"); first <- e }()
	deadline := time.Now().Add(time.Second)
	for f.attestations.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	second := make(chan error, 1)
	go func() { _, e := c.Verify(context.Background(), "canonical/model"); second <- e }()
	cancel()
	if e := <-first; e != context.Canceled {
		t.Fatal(e)
	}
	close(release)
	if e := <-second; e != nil {
		t.Fatal(e)
	}
	if f.attestations.Load() != 1 {
		t.Fatal("duplicate verification")
	}
}
func TestZeroTTLAndResponseExpiry(t *testing.T) {
	f := newFakeCloud(t)
	zero := time.Duration(0)
	c, _ := fakeClient(t, f, func(o *InferenceOptions) { o.AttestationTTL = &zero; o.ResponseTTL = &zero })
	for i := 0; i < 2; i++ {
		if _, e := c.Verify(context.Background(), "canonical/model"); e != nil {
			t.Fatal(e)
		}
	}
	if f.attestations.Load() != 2 {
		t.Fatal("zero TTL cached")
	}
	if _, e := c.CreateChatCompletion(context.Background(), chatRequest()); e != nil {
		t.Fatal(e)
	}
	if len(c.responses) != 0 {
		t.Fatal("zero response TTL retained receipt bytes")
	}
	_, e := c.VerifyResponse(context.Background(), "chat-1")
	requireCode(t, e, "api.completion_not_found")
}
func TestUnconsumedStreamCannotVerify(t *testing.T) {
	for _, encoding := range []string{"", "gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			f := newFakeCloud(t)
			f.stream, f.encoding = true, encoding
			c, _ := fakeClient(t, f, nil)
			body, _ := json.Marshal(chatRequest())
			req, _ := http.NewRequest("POST", c.BaseURL()+"chat/completions", bytes.NewReader(body))
			res, e := c.HTTPClient().Do(req)
			if e != nil {
				t.Fatal(e)
			}
			res.Body.Close()
			_, e = c.VerifyResponse(context.Background(), "chat-1")
			requireCode(t, e, "api.completion_not_found")
		})
	}
}

func TestDoneWithoutIDIsRejectedBeforeExposingIt(t *testing.T) {
	for _, endpoint := range []string{"chat/completions", "responses"} {
		t.Run(endpoint, func(t *testing.T) {
			cloud := newFakeCloud(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/"+endpoint {
					cloud.ServeHTTP(w, r)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				payload := `{"id":"late-id"}`
				if endpoint == "responses" {
					payload = `{"response":{"id":"late-id"}}`
				}
				fmt.Fprintf(w, "data: [DONE]\n\ndata: %s\n\n", payload)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer server.Close()
			client, err := NewInferenceClient(InferenceOptions{
				ClientOptions:       ClientOptions{APIKey: "test", BaseURL: server.URL + "/v1"},
				DisableTLSBinding:   true,
				GatewayVerification: VerificationOptions{QuoteVerifier: fakeQuote},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			body, _ := json.Marshal(chatRequest())
			req, _ := http.NewRequestWithContext(ctx, "POST", client.BaseURL()+endpoint, bytes.NewReader(body))
			response, err := client.HTTPClient().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			_, err = response.Body.Read(make([]byte, 64))
			requireCode(t, err, "api.invalid_response")
			_, err = client.VerifyResponse(context.Background(), "late-id")
			requireCode(t, err, "api.completion_not_found")
		})
	}
}

func TestFailedStreamsAreNotRegistered(t *testing.T) {
	for _, body := range []string{
		"event: error\ndata: {\"error\":\"failed\"}\n\ndata: [DONE]\n\n",
		"data: {\"id\":\"chat-1\",\"error\":\"failed\"}\n\ndata: [DONE]\n\n",
		"data: {\"id\":\"chat-1\"}\n\ndata: {\"id\":\"chat-2\"}\n\ndata: [DONE]\n\n",
		"data: malformed\n\ndata: [DONE]\n\n",
	} {
		f := newFakeCloud(t)
		f.stream = true
		f.streamBody = body
		c, _ := fakeClient(t, f, nil)
		raw, _ := json.Marshal(chatRequest())
		req, _ := http.NewRequest("POST", c.BaseURL()+"chat/completions", bytes.NewReader(raw))
		res, e := c.HTTPClient().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		_, e = io.ReadAll(res.Body)
		res.Body.Close()
		if e == nil {
			t.Fatalf("accepted failed stream %q", body)
		}
		_, e = c.VerifyResponse(context.Background(), "chat-1")
		requireCode(t, e, "api.completion_not_found")
	}
}

func TestVerificationRetriesTransientSignatureStatus(t *testing.T) {
	for _, status := range []int{404, 425, 200} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := newFakeCloud(t)
			c, _ := fakeClient(t, f, nil)
			if _, err := c.CreateChatCompletion(context.Background(), chatRequest()); err != nil {
				t.Fatal(err)
			}
			if status == 200 {
				f.unavailable.Store(true)
			} else {
				f.signatureStatus.Store(int32(status))
			}
			_, err := c.VerifyResponse(context.Background(), "chat-1")
			if status == 200 {
				requireCode(t, err, "api.completion_signature_unavailable")
			} else {
				requireCode(t, err, "api.http_status")
				if sdk, ok := err.(*Error); !ok || !sdk.Retryable {
					t.Fatalf("expected retryable error: %v", err)
				}
			}
			c.mu.Lock()
			record := c.responses["chat-1"]
			retained := len(record.request) > 0 && len(record.response) > 0 && record.session != nil
			c.mu.Unlock()
			if !retained {
				t.Fatal("retryable verification discarded captured bodies")
			}
			f.signatureStatus.Store(0)
			f.unavailable.Store(false)
			if _, err := c.VerifyResponse(context.Background(), "chat-1"); err != nil {
				t.Fatal(err)
			}
			if f.signatureCalls.Load() != 2 {
				t.Fatal("signature was not fetched again")
			}
			c.mu.Lock()
			released := record.request == nil && record.response == nil && record.session == nil
			c.mu.Unlock()
			if !released {
				t.Fatal("successful retry retained captured bodies")
			}
		})
	}
}

func TestSharedResponseVerificationCancellation(t *testing.T) {
	f := newFakeCloud(t)
	wait := make(chan struct{})
	release := sync.OnceFunc(func() { close(wait) })
	defer release()
	f.signatureWait = wait
	c, _ := fakeClient(t, f, nil)
	if _, err := c.CreateChatCompletion(context.Background(), chatRequest()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { _, err := c.VerifyResponse(ctx, "chat-1"); first <- err }()
	deadline := time.Now().Add(time.Second)
	for f.signatureCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.signatureCalls.Load() != 1 {
		t.Fatal("signature lookup did not start")
	}
	second := make(chan error, 1)
	go func() { _, err := c.VerifyResponse(context.Background(), "chat-1"); second <- err }()
	cancel()
	if err := <-first; err != context.Canceled {
		t.Fatal(err)
	}
	c.mu.Lock()
	record := c.responses["chat-1"]
	retained := len(record.request) > 0 && len(record.response) > 0 && record.session != nil
	c.mu.Unlock()
	if !retained {
		t.Fatal("canceled waiter discarded shared verification bodies")
	}
	release()
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if f.signatureCalls.Load() != 1 {
		t.Fatal("shared verification fetched the signature again")
	}
	c.mu.Lock()
	released := record.request == nil && record.response == nil && record.session == nil
	c.mu.Unlock()
	if !released {
		t.Fatal("completed shared verification retained captured bodies")
	}
}

func TestReceiptCacheCopiesBytesAndExpires(t *testing.T) {
	c, err := NewInferenceClient(InferenceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	request, response := []byte("req"), []byte("res")
	if err = c.register("first", request, response, nil, false, 0); err != nil {
		t.Fatal(err)
	}
	request[0], response[0] = 'X', 'X'
	c.mu.Lock()
	first := c.responses["first"]
	c.mu.Unlock()
	if string(first.request) != "req" || string(first.response) != "res" {
		t.Fatal("caller mutated retained receipt")
	}
	// New completions keep earlier receipts available until their TTL expires.
	for i := 0; i < 128; i++ {
		if err = c.register(fmt.Sprint(i), []byte("req"), []byte("res"), nil, false, 0); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	retained := c.responses["first"] != nil && len(c.responses) == 129
	for _, record := range c.responses {
		record.expires = time.Now().Add(-time.Second)
	}
	c.mu.Unlock()
	if !retained {
		t.Fatal("unexpired receipts were discarded")
	}
	if err = c.register("after-expiry", []byte("req"), []byte("res"), nil, false, 0); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	remaining := len(c.responses)
	c.mu.Unlock()
	if remaining != 1 {
		t.Fatal("expired receipt retained")
	}
}

func TestRequestAuthorityUsesConfiguredEndpoint(t *testing.T) {
	f := newFakeCloud(t)
	c, server := fakeClient(t, f, nil)
	defer server.Close()
	defer c.Close()
	r, _ := http.NewRequest("POST", c.BaseURL()+"chat/completions", strings.NewReader(`{"model":"canonical/model","messages":[]}`))
	f.expectedHost = strings.TrimPrefix(server.URL, "http://")
	r.Host = "other.example"
	r.Header.Set("Accept-Encoding", "gzip")
	// The handler observes the configured authority even when a caller overrides Host.
	original := f.chats.Load()
	res, err := c.HTTPClient().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if f.chats.Load() != original+1 {
		t.Fatal("request not served")
	}
}
