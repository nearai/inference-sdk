package nearai

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

//
//go:embed testdata/systemone-responses.json
var systemOneResponseVectors []byte

type systemOneResponseFixture struct {
	Valid   []json.RawMessage
	Invalid map[string]json.RawMessage
}

func systemOneVectors(t *testing.T) systemOneResponseFixture {
	t.Helper()
	var fixture systemOneResponseFixture
	if err := json.Unmarshal(systemOneResponseVectors, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
func TestSystemOneResponseVectors(t *testing.T) {
	fixture := systemOneVectors(t)
	for _, body := range fixture.Valid {
		data, err := decodeSystemOneResponse(body)
		if err != nil {
			t.Fatal(err)
		}
		if data.Answers["__proto__"].Noul == nil || data.Extra["future"] == nil || data.Usage.Extra["extra_tokens"] == nil || data.Answers["__proto__"].Extra["future"] == nil {
			t.Fatal("lost unknown fields or opaque keys")
		}
		answer := data.Answers["region"]
		if answer.Box == nil || string(answer.Box.Extra["future"]) != "true" || string(answer.Extra["future"]) != "true" {
			t.Fatal("lost Box coordinates or unknown fields")
		}
	}
	for name, body := range fixture.Invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSystemOneResponse(body); err == nil {
				t.Fatalf("accepted %s", body)
			}
		})
	}
	if _, err := decodeSystemOneResponse([]byte{'{', 0xff, '}'}); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
}

type systemOneCloud struct {
	f                   *fakeCloud
	body, id            string
	status              int
	tamper, wrongSigner bool
	calls               atomic.Int32
	dropDecisionAt      int32
	truncateBody        bool
	expectedRequest     []byte
}

func (f *systemOneCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/v1/signature/") {
		f.f.signatureCalls.Add(1)
		f.f.mu.Lock()
		sig := f.f.signatures[strings.TrimPrefix(r.URL.Path, "/v1/signature/")]
		f.f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"signature_kind": sig.Kind, "text": sig.SignedText, "signature": sig.Signature, "signing_algo": sig.Signer.SigningAlgo, "signing_address": sig.Signer.SigningAddress})
		return
	}
	if r.URL.Path != "/v1/systemone" {
		f.f.ServeHTTP(w, r)
		return
	}
	if f.calls.Add(1) == f.dropDecisionAt {
		// Consume the request, then lose the response on a reused connection.
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			f.f.t.Error(err)
			return
		}
		_ = conn.Close()
		return
	}
	if r.Header.Get("Authorization") != "Bearer test" || r.Header.Get("Api-Key") != "" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get(NoAliasingHeader) != "true" {
		f.f.t.Errorf("incorrect owned headers: %v", r.Header)
	}
	wantKey := ""
	if f.f.tee {
		wantKey = f.f.a.SigningPublicKey
		if f.f.a.Signer.SigningAlgo == ECDSA {
			wantKey = strings.TrimPrefix(wantKey, "04")
		}
		if f.f.extraModel {
			wantKey = strings.Repeat("22", 32)
		}
	}
	if r.Header.Get("X-Model-Pub-Key") != wantKey {
		f.f.t.Errorf("model routing key = %q, want %q", r.Header.Get("X-Model-Pub-Key"), wantKey)
	}
	for _, name := range []string{"X-Client-Pub-Key", "X-Signing-Algo", "Digest", "Content-Encoding"} {
		if r.Header.Get(name) != "" {
			f.f.t.Errorf("unexpected %s", name)
		}
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	body, _ := io.ReadAll(r.Body)
	if f.expectedRequest != nil && !bytes.Equal(body, f.expectedRequest) {
		f.f.t.Errorf("System One changed the JSON image request: %s", body)
	}
	sig := f.f.completionSignature(body, []byte(f.body), f.f.tee)
	if f.wrongSigner {
		sig.Signer.SigningAddress = strings.Repeat("11", len(sig.Signer.SigningAddress)/2)
	}
	f.f.mu.Lock()
	f.f.signatures[f.id] = sig
	f.f.mu.Unlock()
	w.Header().Set("X-Generation-Id", f.id)
	if f.truncateBody {
		w.Header().Set("Content-Length", strconv.Itoa(len(f.body)+1))
	}
	wire := f.body
	if f.tamper {
		wire += " "
	}
	writeEncodedResponse(f.f.t, w, []byte(wire), f.f.encoding)
}
func systemOneClient(t *testing.T, tee bool, algo SigningAlgo, modify func(*systemOneCloud, *InferenceOptions)) (*InferenceClient, *systemOneCloud) {
	t.Helper()
	f := &systemOneCloud{f: newFakeCloud(t), id: "decision/with % space", body: " \n" + string(systemOneVectors(t).Valid[0]) + " \n"}
	f.f.tee = tee
	if algo == ECDSA {
		f.f.useECDSA()
		// Exercise normalization of an uncompressed public key with its 04 prefix.
		f.f.a.SigningPublicKey = "04" + f.f.a.SigningPublicKey
	}
	c, _ := fakeClient(t, f, func(o *InferenceOptions) {
		o.SigningAlgo = algo
		if modify != nil {
			modify(f, o)
		}
	})
	return c, f
}
func systemOneRequest() any {
	return map[string]any{"model": "canonical/model", "state": map[string]string{"text": "hello"}, "questions": map[string]any{"q": map[string]string{"type": "noul", "instructions": "Is this a greeting?"}}}
}

func TestSystemOneClearResponseCache(t *testing.T) {
	c, _ := systemOneClient(t, true, Ed25519, nil)
	for i := 0; i < 2; i++ {
		result, err := c.CreateSystemOne(context.Background(), systemOneRequest())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.VerifyResponse(context.Background(), result.DecisionID); err != nil {
			t.Fatal(err)
		}
		c.ClearResponseCache()
		_, err = c.VerifyResponse(context.Background(), result.DecisionID)
		requireCode(t, err, "api.completion_not_found")
	}
}

func TestSystemOnePlaintextKeyRoutingAndReceipt(t *testing.T) {
	for _, tee := range []bool{false, true} {
		for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
			t.Run(fmt.Sprintf("tee=%t/%s", tee, algo), func(t *testing.T) {
				c, f := systemOneClient(t, tee, algo, nil)
				headers := http.Header{"Authorization": {"Bearer bad"}, "Api-Key": {"bad"}, "Accept-Encoding": {"gzip"}, "Content-Encoding": {"gzip"}, "X-Model-Pub-Key": {"bad"}, "Digest": {"bad"}}
				result, err := c.CreateSystemOneWithHeaders(context.Background(), systemOneRequest(), headers)
				if err != nil {
					t.Fatal(err)
				}
				if result.DecisionID != f.id || result.Data.ID != nil {
					t.Fatal("receipt ID must come from header")
				}
				result.Data.Model = "mutated"
				receipt, err := c.VerifyResponse(context.Background(), result.DecisionID)
				if err != nil {
					t.Fatal(err)
				}
				if receipt.ID != result.DecisionID || receipt.CompletionID != receipt.ID {
					t.Fatal("receipt ID alias mismatch")
				}
				if receipt.SignatureKind != map[bool]string{true: "provider_tee", false: "gateway"}[tee] {
					t.Fatal("wrong attribution")
				}
				if _, err = c.VerifyResponse(context.Background(), result.DecisionID); err != nil || f.f.signatureCalls.Load() != 1 {
					t.Fatal("receipt verification not memoized", err)
				}
			})
		}
	}
}
func TestSystemOnePreservesJSONImagesAndBoxReceipts(t *testing.T) {
	image := map[string]any{"type": "image_url", "image_url": map[string]string{"url": "data:image/png;base64,ZmFrZS1pbWFnZQ=="}}
	request := SystemOneRequest{
		Model: "canonical/model", State: map[string]any{"canvas": image},
		Questions: map[string]SystemOneQuestion{
			"region":  {Type: "box", Instructions: []any{"Locate the rectangle", image}},
			"present": {Type: "noul", Instructions: "Does the canvas match?", Criteria: map[string]any{"true": image}},
		},
	}
	for _, assets := range []bool{false, true} {
		if assets {
			request.Assets = map[string]SystemOneImageAsset{"<photo>": {Format: "png", DataBase64: "ZmFrZS1pbWFnZQ=="}}
			request.State = map[string]any{"canvas": []any{"<photo>", image}}
			request.Questions["region"] = SystemOneQuestion{Type: "box", Instructions: "Locate <photo> now"}
			request.Questions["present"] = SystemOneQuestion{Type: "noul", Instructions: "Does it match?", Criteria: map[string]any{"true": "<photo>"}}
		}
		expected, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
			t.Run(string(algo), func(t *testing.T) {
				c, f := systemOneClient(t, false, algo, func(f *systemOneCloud, _ *InferenceOptions) {
					f.expectedRequest = expected
				})
				result, err := c.CreateSystemOne(context.Background(), request)
				if err != nil {
					t.Fatal(err)
				}
				answer := result.Data.Answers["region"]
				if answer.Box == nil || answer.Box.Top != 0.31 || answer.Confidence == nil || *answer.Confidence != 0.82 {
					t.Fatalf("wrong box answer: %+v", answer)
				}
				answer.Box.Top = 0
				receipt, err := c.VerifyResponse(context.Background(), result.DecisionID)
				if err != nil {
					t.Fatal(err)
				}
				if receipt.SignatureKind != "gateway" || f.calls.Load() != 1 || f.f.signatureCalls.Load() != 1 {
					t.Fatal("expected one request and its Gateway receipt")
				}
			})
		}
	}
}

func TestSystemOneRejectsAnotherVerifiedSigner(t *testing.T) {
	c, _ := systemOneClient(t, true, Ed25519, func(f *systemOneCloud, _ *InferenceOptions) {
		f.f.extraModel = true
	})
	result, err := c.CreateSystemOne(context.Background(), systemOneRequest())
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.VerifyResponse(context.Background(), result.DecisionID)
	requireCode(t, err, "signature.signer_mismatch")
}

func TestSystemOneCompressedResponses(t *testing.T) {
	for _, encoding := range []string{"gzip", "br"} {
		for _, mode := range []string{"receipt", "tamper", "padded"} {
			t.Run(encoding+"/"+mode, func(t *testing.T) {
				c, f := systemOneClient(t, true, Ed25519, func(f *systemOneCloud, o *InferenceOptions) {
					f.f.encoding = encoding
					f.tamper = mode == "tamper"
					if mode == "padded" {
						f.body += strings.Repeat(" ", 4096)
					}
				})
				result, err := c.CreateSystemOne(context.Background(), systemOneRequest())
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.VerifyResponse(context.Background(), result.DecisionID)
				if mode == "tamper" {
					requireCode(t, err, "signature.payload_mismatch")
				} else if err != nil {
					t.Fatal(err)
				}
				if f.calls.Load() != 1 {
					t.Fatal("compressed response repeated inference")
				}
			})
		}
	}
}

func TestSystemOneSharesChatSession(t *testing.T) {
	for _, decisionFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(decisionFirst), func(t *testing.T) {
			c, f := systemOneClient(t, true, Ed25519, nil)
			ctx := context.Background()
			chat := func() error {
				_, err := c.CreateChatCompletion(ctx, chatRequest())
				return err
			}
			decision := func() error {
				_, err := c.CreateSystemOne(ctx, systemOneRequest())
				return err
			}
			calls := []func() error{chat, decision}
			if decisionFirst {
				calls[0], calls[1] = calls[1], calls[0]
			}
			for _, call := range calls {
				if err := call(); err != nil {
					t.Fatal(err)
				}
			}
			if f.f.attestations.Load() != 2 {
				t.Fatalf("expected one Gateway and one model report, got %d", f.f.attestations.Load())
			}
		})
	}
}

func TestSystemOneFailuresAndUnsupportedRequests(t *testing.T) {
	for _, mode := range []string{"429", "503", "truncated", "invalid", "id", "tamper", "signer", "bad-model", "missing-key", "e2ee", "ohttp", "stream"} {
		t.Run(mode, func(t *testing.T) {
			c, f := systemOneClient(t, true, Ed25519, func(f *systemOneCloud, o *InferenceOptions) {
				switch mode {
				case "429":
					f.status = 429
				case "503":
					f.status = 503
				case "truncated":
					f.truncateBody = true
				case "invalid":
					f.body = "{}"
				case "id":
					f.id = ""
				case "tamper":
					f.tamper = true
				case "signer":
					f.wrongSigner = true
				case "bad-model":
					f.f.badModel = true
				case "missing-key":
					f.f.missingModelKey = true
				case "e2ee":
					o.E2EE = true
				case "ohttp":
					o.OHTTP = true
				}
			})
			request := systemOneRequest().(map[string]any)
			if mode == "stream" {
				request["stream"] = false
			}
			result, err := c.CreateSystemOne(context.Background(), request)
			if mode == "tamper" || mode == "signer" {
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.VerifyResponse(context.Background(), result.DecisionID)
			}
			if err == nil {
				t.Fatal("expected failure")
			}
			if mode == "429" || mode == "503" {
				requireCode(t, err, "api.http_status")
				if err.(*Error).Retryable {
					t.Fatal("inference failure must not suggest replay")
				}
			}
			if mode == "truncated" {
				requireCode(t, err, "api.transport_failed")
				if err.(*Error).Retryable || err.(*Error).Details["reason"] != "response_body" {
					t.Fatalf("wrong body error: %#v", err)
				}
			}
			want := int32(1)
			if mode == "bad-model" || mode == "missing-key" || mode == "e2ee" || mode == "ohttp" || mode == "stream" || mode == "direct" {
				want = 0
			}
			if f.calls.Load() != want {
				t.Fatalf("sent %d requests, want %d", f.calls.Load(), want)
			}
		})
	}
}
func TestSystemOneCancellationAndClose(t *testing.T) {
	c, _ := systemOneClient(t, false, Ed25519, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.CreateSystemOne(ctx, systemOneRequest())
	if err != context.Canceled {
		t.Fatal(err)
	}
	_ = c.Close()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = c.CreateSystemOne(ctx, systemOneRequest())
	requireCode(t, err, "api.client_closed")
}

func TestSystemOneDoesNotReplayAfterConnectionFailure(t *testing.T) {
	for _, tc := range []struct {
		header, source string
		value          []string
	}{
		{"", "none", nil},
		{"Idempotency-Key", "client", []string{"decision-key"}},
		{"Idempotency-Key", "call", []string{"decision-key"}},
		{"X-Idempotency-Key", "client", []string{"decision-key"}},
		{"X-Idempotency-Key", "call", []string{"decision-key"}},
		{"Idempotency-Key", "client-empty", []string{}},
		{"Idempotency-Key", "call-empty", []string{}},
	} {
		t.Run(tc.header+"/"+tc.source, func(t *testing.T) {
			transport := &http.Transport{}
			t.Cleanup(transport.CloseIdleConnections)
			c, f := systemOneClient(t, false, Ed25519, func(f *systemOneCloud, o *InferenceOptions) {
				f.dropDecisionAt = 2
				o.HTTPClient = &http.Client{Transport: transport}
				if strings.HasPrefix(tc.source, "client") {
					o.Headers = http.Header{tc.header: tc.value}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.CreateSystemOne(ctx, systemOneRequest()); err != nil {
				t.Fatal(err)
			}
			var reused atomic.Bool
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
				GotConn: func(info httptrace.GotConnInfo) {
					if info.Reused {
						reused.Store(true)
					}
				},
			})
			var headers http.Header
			if strings.HasPrefix(tc.source, "call") {
				headers = http.Header{tc.header: tc.value}
			}
			_, err := c.CreateSystemOneWithHeaders(ctx, systemOneRequest(), headers)
			if !reused.Load() {
				t.Fatal("did not exercise a reused connection")
			}
			if f.calls.Load() != 2 {
				t.Fatalf("decision was replayed: %d requests, want warmup + one failed request", f.calls.Load())
			}
			requireCode(t, err, "api.transport_failed")
			if err.(*Error).Retryable || err.(*Error).Details["reason"] != "request" {
				t.Fatalf("wrong inference transport error: %#v", err)
			}
		})
	}
}

func TestSystemOnePreservesStructuredLegendNumbers(t *testing.T) {
	for _, number := range []string{"9007199254740993", "-9007199254740993", "0.12345678901234567890123456789", "1e400", "-0"} {
		t.Run(number, func(t *testing.T) {
			wire := fmt.Sprintf(`{"model":"canonical/model","answers":{"q":{"type":"score","score":1.5,"confidence":0.9,"probabilities":{"1":1},"legend":{"1":{"value":%s},"2":[%s,{"value":%s}],"3":"text"}}},"usage":{"input_tokens":1,"output_tokens":1}}`, number, number, number)
			c, _ := systemOneClient(t, false, Ed25519, func(f *systemOneCloud, _ *InferenceOptions) { f.body = wire })
			result, err := c.CreateSystemOne(context.Background(), systemOneRequest())
			if err != nil {
				t.Fatal(err)
			}
			answer := result.Data.Answers["q"]
			nested := answer.Legend["1"].(map[string]any)["value"]
			array := answer.Legend["2"].([]any)
			for _, value := range []any{nested, array[0], array[1].(map[string]any)["value"]} {
				n, ok := value.(json.Number)
				if !ok || n.String() != number {
					t.Fatalf("number changed: %#v (%T), want json.Number(%s)", value, value, number)
				}
			}
			if answer.Score == nil || *answer.Score != 1.5 || answer.Probabilities["1"] != 1 {
				t.Fatal("typed numeric answer fields changed")
			}
			encoded, err := json.Marshal(answer.Legend)
			if err != nil || !bytes.Contains(encoded, []byte(`"value":`+number)) {
				t.Fatalf("roundtrip lost number: %s, %v", encoded, err)
			}
			if _, err := c.VerifyResponse(context.Background(), result.DecisionID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
