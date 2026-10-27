package nearai

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeCloud struct {
	expectedHost    string
	encrypt         bool
	streamBody      string
	encoding        string
	t               *testing.T
	a               Attestation
	q               QuoteVerificationResult
	priv            ed25519.PrivateKey
	mu              sync.Mutex
	signatureStatus atomic.Int32
	signatureCalls  atomic.Int32
	signatures      map[string]CompletionSignature
	next            int
	attestations    atomic.Int32
	chats           atomic.Int32
	dropChatAt      int32
	extraModel      bool
	missingModelKey bool
	tee             bool
	direct          bool
	stream          bool
	tamper          bool
	badModel        bool
	slow            <-chan struct{}
}

func newFakeCloud(t *testing.T) *fakeCloud {
	a, q, key := attestationFixture(t, Ed25519)
	return &fakeCloud{t: t, a: a, q: q, priv: key, signatures: map[string]CompletionSignature{}}
}
func (f *fakeCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/chat/completions" && r.Header.Get("Accept-Encoding") != "identity" {
		f.t.Errorf("Chat did not force identity encoding")
	}
	if f.expectedHost != "" && r.Host != f.expectedHost {
		f.t.Errorf("unexpected authority %q", r.Host)
	}
	if strings.HasSuffix(r.URL.Path, "/attestation/report") {
		for _, name := range []string{"Authorization", "Api-Key", "X-Api-Key"} {
			if r.Header.Get(name) != "" {
				f.t.Errorf("attestation sent %s", name)
			}
		}
	} else if r.Header.Get("Authorization") != "Bearer test" {
		http.Error(w, "bad auth", 401)
		return
	}
	switch {
	case strings.Contains(r.URL.Path, "/model/"):
		if r.URL.EscapedPath() != "/v1/model/canonical%2Fmodel" {
			f.t.Errorf("model URL %s", r.URL.EscapedPath())
		}
		provider := "proxy"
		if f.tee {
			provider = "vllm"
		}
		json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"providerType": provider, "attestationSupported": f.tee}})
	case strings.HasSuffix(r.URL.Path, "/attestation/report"):
		f.attestations.Add(1)
		if f.slow != nil {
			<-f.slow
		}
		n := r.URL.Query().Get("nonce")
		nb, _ := unhex(n)
		report := append([]byte(nil), f.q.ReportData...)
		copy(report[32:], nb)
		q := f.q
		q.ReportData = report
		quote, _ := json.Marshal(q)
		a := map[string]any{
			"request_nonce":      n,
			"signing_algo":       f.a.Signer.SigningAlgo,
			"signing_address":    f.a.Signer.SigningAddress,
			"signing_public_key": f.a.SigningPublicKey,
			"intel_quote":        string(quote),
			"event_log":          f.a.EventLog,
			"report_data":        hex.EncodeToString(report),
			"info":               map[string]any{"tcb_info": map[string]any{"app_compose": f.a.AppCompose}},
		}
		if f.a.ComposeManagerAttestation != nil && (f.direct || r.URL.Query().Get("model") != "") {
			manager := *f.a.ComposeManagerAttestation
			manager.Nonce = n
			managerQuote := q
			managerQuote.ReportData = bytes.Clone(report)
			actionsHash, _ := hex.DecodeString(manager.ActionsHash)
			copy(managerQuote.ReportData, actionsHash)
			managerQuoteBytes, _ := json.Marshal(managerQuote)
			manager.IntelQuote = string(managerQuoteBytes)
			a["compose_manager_attestation"] = manager
		}
		if f.direct {
			a["model_name"] = "canonical/model"
			root := maps.Clone(a)
			root["all_attestations"] = []any{a}
			json.NewEncoder(w).Encode(root)
		} else if r.URL.Query().Get("model") != "" {
			if f.missingModelKey {
				delete(a, "signing_public_key")
			}
			items := []any{a}
			if f.extraModel {
				other := maps.Clone(a)
				other["signing_address"] = strings.Repeat("22", 32)
				other["signing_public_key"] = other["signing_address"]
				report := append([]byte(nil), q.ReportData...)
				for i := 0; i < 32; i++ {
					report[i] = 0x22
				}
				otherQuote := q
				otherQuote.ReportData = report
				encoded, _ := json.Marshal(otherQuote)
				other["intel_quote"] = string(encoded)
				other["report_data"] = hex.EncodeToString(report)
				items = append([]any{other}, items...)
			}

			if f.badModel {
				bad := map[string]any{}
				for k, v := range a {
					bad[k] = v
				}
				bad["signing_address"] = strings.Repeat("22", 32)
				items = append(items, bad)
			}
			json.NewEncoder(w).Encode(map[string]any{"model_attestations": items})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"gateway_attestation": a})
		}
	case strings.HasSuffix(r.URL.Path, "/chat/completions"):
		if f.chats.Add(1) == f.dropChatAt {
			_, _ = io.Copy(io.Discard, r.Body)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				f.t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		if f.encrypt {
			if r.Header.Get("X-Signing-Algo") != "ed25519" {
				f.t.Error("missing E2EE signing algorithm")
			}
		} else if r.Header.Get("X-Signing-Algo") != "" || r.Header.Get("X-Client-Pub-Key") != "" {
			f.t.Error("E2EE headers on plaintext request")
		}
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get(NoAliasingHeader) != "true" {
			f.t.Error("missing no-aliasing")
		}
		f.mu.Lock()
		f.next++
		id := "chat-" + itoa(f.next)
		f.mu.Unlock()
		reply := `{"id":"` + id + `","choices":[{"message":{"content":"answer"}}]}`
		if f.stream {
			reply = "data: {\"id\":\"" + id + "\",\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\r\n\r\ndata: [DONE]\r\n\r\n"
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		if f.encrypt {
			var input map[string]any
			json.Unmarshal(body, &input)
			content, _ := objects(input["messages"])[0]["content"].(string)
			seed := f.priv.Seed()
			h := sha512.Sum512(seed)
			secret := h[:32]
			secret[0] &= 248
			secret[31] &= 127
			secret[31] |= 64
			message, err := decryptText(content, e2eeKey{algo: Ed25519, secret: secret})
			if err != nil || message != "review" {
				f.t.Errorf("E2EE request: %q %v", message, err)
			}
			encrypted, err := encryptText("answer", E2EEModelKey{Ed25519, r.Header.Get("X-Client-Pub-Key")})
			if err != nil {
				f.t.Error(err)
			}
			reply = strings.ReplaceAll(reply, "answer", encrypted)
		}
		if f.streamBody != "" {
			reply = f.streamBody
		}
		kind := "gateway"
		text := hashText(body) + ":" + hashText([]byte(reply))
		if f.tee {
			kind = "provider_tee"
			text = "canonical/model:" + text
		}
		sig := CompletionSignature{kind, text, hex.EncodeToString(ed25519.Sign(f.priv, []byte(text))), f.a.Signer}
		f.mu.Lock()
		f.signatures[id] = sig
		f.mu.Unlock()
		if f.tamper {
			reply = strings.ReplaceAll(reply, "answer", "altered")
		}
		writeEncodedResponse(f.t, w, []byte(reply), f.encoding)
	case strings.Contains(r.URL.Path, "/signature/"):
		f.signatureCalls.Add(1)
		if status := f.signatureStatus.Load(); status != 0 {
			w.WriteHeader(int(status))
			return
		}
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		f.mu.Lock()
		sig := f.signatures[id]
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"signature_kind":  sig.Kind,
			"text":            sig.SignedText,
			"signature":       sig.Signature,
			"signing_algo":    sig.Signer.SigningAlgo,
			"signing_address": sig.Signer.SigningAddress,
		})
	default:
		http.NotFound(w, r)
	}
}
func fakeQuote(ctx context.Context, raw string) (QuoteVerificationResult, error) {
	var q QuoteVerificationResult
	e := json.Unmarshal([]byte(raw), &q)
	return q, e
}
func fakeClient(t *testing.T, f *fakeCloud, modify func(*InferenceOptions)) (*InferenceClient, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(f)
	o := InferenceOptions{
		ClientOptions:       ClientOptions{APIKey: "test", BaseURL: server.URL + "/v1"},
		DisableTLSBinding:   true,
		GatewayVerification: VerificationOptions{QuoteVerifier: fakeQuote},
		ModelVerification:   VerificationOptions{QuoteVerifier: fakeQuote},
	}
	if modify != nil {
		modify(&o)
	}
	c, e := NewInferenceClient(o)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close(); server.Close() })
	return c, server
}
func chatRequest() map[string]any {
	return map[string]any{"model": "canonical/model", "messages": []any{map[string]any{"role": "user", "content": "review"}}}
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
			t.Run(itoa(boolInt(tee))+itoa(boolInt(stream)), func(t *testing.T) {
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
				if first.Gateway != nil {
					first.Gateway.Signer.SigningAddress = "mutated"
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

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestProviderReceiptManagerEvidenceDoesNotAliasCachedResults(t *testing.T) {
	f := newFakeCloud(t)
	f.tee = true
	f.q.AdvisoryIDs = []string{"original-advisory"}
	fixture := loadManagerFixture(t)
	f.a.ComposeManagerAttestation = &ComposeManagerAttestation{Actions: fixture.Actions, ActionsHash: fixture.ActionsHash, EventLog: f.a.EventLog}
	client, _ := fakeClient(t, f, nil)
	ctx := context.Background()
	if _, err := client.CreateChatCompletion(ctx, chatRequest()); err != nil {
		t.Fatal(err)
	}
	before, err := client.Verify(ctx, "canonical/model")
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.VerifyResponse(ctx, "chat-1")
	if err != nil {
		t.Fatal(err)
	}
	manager := first.Attestation.Deployment.ComposeManager
	manager.Actions[0]["tag"] = "mutated"
	manager.Actions[0]["services"].([]string)[0] = "mutated"
	manager.AdvisoryIDs[0] = "mutated"
	manager.RuntimeMeasurements.ComposeHash = "mutated"
	second, err := client.VerifyResponse(ctx, "chat-1")
	if err != nil {
		t.Fatal(err)
	}
	after, err := client.Verify(ctx, "canonical/model")
	if err != nil {
		t.Fatal(err)
	}
	want := before.Models[0].Deployment.ComposeManager
	if !reflect.DeepEqual(second.Attestation.Deployment.ComposeManager, want) || !reflect.DeepEqual(after.Models[0].Deployment.ComposeManager, want) {
		t.Fatal("mutating a receipt changed cached manager evidence")
	}
	if f.signatureCalls.Load() != 1 || f.attestations.Load() != 2 {
		t.Fatal("expected cached receipt and session results")
	}
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
	for _, name := range []string{"E2EE", "model policy", "invalid second model"} {
		t.Run(name, func(t *testing.T) {
			f := newFakeCloud(t)
			if name == "invalid second model" {
				f.tee = true
				f.badModel = true
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
func TestPinnedTLSRejectsBeforeSending(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); io.WriteString(w, "ok") }))
	defer server.Close()
	base := server.Client().Transport.(*http.Transport)
	base = base.Clone()
	base.TLSClientConfig.InsecureSkipVerify = false
	base.TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	// httptest's client trusts its certificate through RootCAs.
	transport, e := NewPinnedTransport(base, strings.Repeat("00", 32))
	if e != nil {
		t.Fatal(e)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	if _, e = client.Get(server.URL); e == nil {
		t.Fatal("wrong pin accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("request sent before pin checked")
	}
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

func TestSuccessfulE2EEInference(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(itoa(boolInt(stream)), func(t *testing.T) {
			f := newFakeCloud(t)
			f.tee = true
			f.encrypt = true
			f.stream = stream
			c, _ := fakeClient(t, f, func(o *InferenceOptions) { o.E2EE = true })
			body, _ := json.Marshal(chatRequest())
			req, _ := http.NewRequest("POST", c.BaseURL()+"chat/completions", bytes.NewReader(body))
			res, e := c.HTTPClient().Do(req)
			if e != nil {
				t.Fatal(e)
			}
			visible, e := io.ReadAll(res.Body)
			res.Body.Close()
			if e != nil || !bytes.Contains(visible, []byte("answer")) {
				t.Fatalf("response=%s err=%v", visible, e)
			}
			if _, e = c.VerifyResponse(context.Background(), "chat-1"); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestDirectClientE2EEIsOptIn(t *testing.T) {
	for _, e2ee := range []bool{false, true} {
		name := "default plaintext"
		if e2ee {
			name = "explicit E2EE"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeCloud(t)
			f.tee, f.direct, f.encrypt = true, true, e2ee
			server := httptest.NewServer(f)
			defer server.Close()
			opts := DirectInferenceOptions{InferenceOptions: InferenceOptions{
				ClientOptions:     ClientOptions{APIKey: "test", BaseURL: server.URL + "/v1"},
				ModelVerification: VerificationOptions{QuoteVerifier: fakeQuote},
			}}
			if e2ee {
				opts.E2EE = true
			}
			client, err := NewDirectInferenceClient(opts)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			body, err := client.CreateChatCompletion(context.Background(), chatRequest())
			if err != nil || !bytes.Contains(body, []byte("answer")) {
				t.Fatalf("response=%s err=%v", body, err)
			}
			if _, err := client.VerifyResponse(context.Background(), "chat-1"); err != nil {
				t.Fatal(err)
			}
			if f.attestations.Load() != 1 {
				t.Fatal("expected model preflight")
			}
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
	for _, status := range []int{404, 425} {
		t.Run(itoa(status), func(t *testing.T) {
			f := newFakeCloud(t)
			c, _ := fakeClient(t, f, nil)
			if _, err := c.CreateChatCompletion(context.Background(), chatRequest()); err != nil {
				t.Fatal(err)
			}
			f.signatureStatus.Store(int32(status))
			_, err := c.VerifyResponse(context.Background(), "chat-1")
			requireCode(t, err, "api.http_status")
			if sdk, ok := err.(*Error); !ok || !sdk.Retryable {
				t.Fatalf("expected retryable error: %v", err)
			}
			f.signatureStatus.Store(0)
			if _, err := c.VerifyResponse(context.Background(), "chat-1"); err != nil {
				t.Fatal(err)
			}
			if f.signatureCalls.Load() != 2 {
				t.Fatal("signature was not fetched again")
			}
		})
	}
}

func TestReceiptCacheCopiesBytesAndExpires(t *testing.T) {
	c, err := NewInferenceClient(InferenceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	request, response := []byte("req"), []byte("res")
	if err = c.register("first", request, response, nil, false); err != nil {
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
		if err = c.register(fmt.Sprint(i), []byte("req"), []byte("res"), nil, false); err != nil {
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
	if err = c.register("after-expiry", []byte("req"), []byte("res"), nil, false); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	remaining := len(c.responses)
	c.mu.Unlock()
	if remaining != 1 {
		t.Fatal("expired receipt retained")
	}
}

func TestUnsupportedEndpointBeforePreflight(t *testing.T) {
	f := newFakeCloud(t)
	c, server := fakeClient(t, f, nil)
	defer server.Close()
	defer c.Close()
	for _, endpoint := range []string{"responses/resp_fixture", "messages"} {
		r, err := http.NewRequest("POST", c.BaseURL()+endpoint, strings.NewReader(`{"model":"canonical/model"}`))
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.HTTPClient().Do(r)
		requireCode(t, err, "api.invalid_input")
	}
	if f.attestations.Load() != 0 || f.chats.Load() != 0 {
		t.Fatal("unsupported endpoint performed network I/O")
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
