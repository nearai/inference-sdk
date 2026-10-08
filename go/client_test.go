package nearai

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeCloud struct {
	encrypt         bool
	streamBody      string
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
	tee             bool
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
	if r.Header.Get("Authorization") != "Bearer test" {
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
		a := map[string]any{"request_nonce": n, "signing_algo": "ed25519", "signing_address": f.a.Signer.SigningAddress, "signing_public_key": f.a.SigningPublicKey, "intel_quote": string(quote), "event_log": f.a.EventLog, "report_data": hex.EncodeToString(report), "info": map[string]any{"tcb_info": map[string]any{"app_compose": f.a.AppCompose}}}
		if r.URL.Query().Get("model") != "" {
			items := []any{a}
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
		f.chats.Add(1)
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
		io.WriteString(w, reply)
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
		json.NewEncoder(w).Encode(map[string]any{"signature_kind": sig.Kind, "text": sig.SignedText, "signature": sig.Signature, "signing_algo": sig.Signer.SigningAlgo, "signing_address": sig.Signer.SigningAddress})
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
	o := InferenceOptions{ClientOptions: ClientOptions{APIKey: "test", BaseURL: server.URL + "/v1"}, DisableTLSBinding: true, GatewayVerification: VerificationOptions{QuoteVerifier: fakeQuote}, ModelVerification: VerificationOptions{QuoteVerifier: fakeQuote}}
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
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
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
	f := newFakeCloud(t)
	f.stream = true
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
