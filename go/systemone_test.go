package nearai

import (
	"context"
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Keep this copy in sync with rs/test-fixtures/systemone-responses.json.
//
//go:embed testdata/systemone-responses.json
var systemOneResponseVectors []byte

func systemOneVectors(t *testing.T) map[string][]json.RawMessage {
	t.Helper()
	var fixture map[string][]json.RawMessage
	if err := json.Unmarshal(systemOneResponseVectors, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
func TestSystemOneSharedResponseVectors(t *testing.T) {
	fixture := systemOneVectors(t)
	for _, body := range fixture["valid"] {
		data, err := decodeSystemOneResponse(body)
		if err != nil {
			t.Fatal(err)
		}
		if data.Answers["__proto__"].Noul == nil || data.Extra["future"] == nil || data.Usage.Extra["extra_tokens"] == nil || data.Answers["__proto__"].Extra["future"] == nil {
			t.Fatal("lost unknown fields or opaque keys")
		}
	}
	for _, body := range fixture["invalid"] {
		if _, err := decodeSystemOneResponse(body); err == nil {
			t.Fatalf("accepted %s", body)
		}
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
	sharedSigner        bool
	key                 *secp.PrivateKey
	calls               atomic.Int32
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
	if f.sharedSigner && r.URL.Path == "/v1/attestation/report" && r.URL.Query().Get("model") != "" {
		recorder := httptest.NewRecorder()
		f.f.ServeHTTP(recorder, r)
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			f.f.t.Fatal(err)
		}
		reports := body["model_attestations"].([]any)
		// fakeCloud appends the actual receipt signer after an unrelated report.
		body["model_attestations"] = append(reports, reports[len(reports)-1])
		_ = json.NewEncoder(w).Encode(body)
		return
	}
	if r.URL.Path != "/v1/systemone" {
		f.f.ServeHTTP(w, r)
		return
	}
	f.calls.Add(1)
	if r.Header.Get("Authorization") != "Bearer test" || r.Header.Get("Api-Key") != "" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get(NoAliasingHeader) != "true" {
		f.f.t.Errorf("incorrect owned headers: %v", r.Header)
	}
	for _, name := range []string{"X-Model-Pub-Key", "X-Client-Pub-Key", "X-Signing-Algo", "Digest", "Content-Encoding"} {
		if r.Header.Get(name) != "" {
			f.f.t.Errorf("unexpected %s", name)
		}
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	body, _ := io.ReadAll(r.Body)
	kind := "gateway"
	text := hashText(body) + ":" + hashText([]byte(f.body))
	if f.f.tee {
		kind = "provider_tee"
		text = "canonical/model:" + text
	}
	sig := CompletionSignature{Kind: kind, SignedText: text, Signer: f.f.a.Signer}
	if f.key == nil {
		sig.Signature = hex.EncodeToString(ed25519.Sign(f.f.priv, []byte(text)))
	} else {
		digest := keccak([]byte("\x19Ethereum Signed Message:\n" + itoa(len(text)) + text))
		compact := secpecdsa.SignCompact(f.key, digest, false)
		sig.Signature = hex.EncodeToString(append(compact[1:], compact[0]))
	}
	if f.wrongSigner {
		sig.Signer.SigningAddress = strings.Repeat("11", len(sig.Signer.SigningAddress)/2)
	}
	f.f.mu.Lock()
	f.f.signatures[f.id] = sig
	f.f.mu.Unlock()
	w.Header().Set("X-Generation-Id", f.id)
	_, _ = io.WriteString(w, f.body)
	if f.tamper {
		_, _ = io.WriteString(w, " ")
	}
}
func systemOneClient(t *testing.T, tee bool, algo SigningAlgo, modify func(*systemOneCloud, *InferenceOptions)) (*InferenceClient, *systemOneCloud) {
	t.Helper()
	f := &systemOneCloud{f: newFakeCloud(t), id: "decision/with % space", body: " \n" + string(systemOneVectors(t)["valid"][0]) + " \n"}
	f.f.tee, f.f.missingModelKey = tee, true
	f.f.extraModel = tee && algo == Ed25519
	if algo == ECDSA {
		f.key, _ = secp.GeneratePrivateKey()
		address := keccak(f.key.PubKey().SerializeUncompressed()[1:])[12:]
		f.f.a.Signer = SigningIdentity{ECDSA, hex.EncodeToString(address)}
		f.f.a.SigningPublicKey = hex.EncodeToString(f.key.PubKey().SerializeUncompressed())
		clear(f.f.q.ReportData[:32])
		copy(f.f.q.ReportData, address)
	}
	server := httptest.NewServer(f)
	o := InferenceOptions{ClientOptions: ClientOptions{APIKey: "test", BaseURL: server.URL + "/v1"}, SigningAlgo: algo, DisableTLSBinding: true, GatewayVerification: VerificationOptions{QuoteVerifier: fakeQuote}, ModelVerification: VerificationOptions{QuoteVerifier: fakeQuote}}
	if modify != nil {
		modify(f, &o)
	}
	c, err := NewInferenceClient(o)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); server.Close() })
	return c, f
}
func systemOneRequest() any {
	return map[string]any{"model": "canonical/model", "state": map[string]string{"text": "hello"}, "questions": map[string]any{"q": map[string]string{"type": "noul", "instructions": "Is this a greeting?"}}}
}

func TestSystemOneExactBytesAndReceiptWithoutEncryptionKey(t *testing.T) {
	for _, tee := range []bool{false, true} {
		for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
			t.Run(itoa(boolInt(tee))+string(algo), func(t *testing.T) {
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
				if receipt.SignatureKind != map[bool]string{true: "provider_tee", false: "gateway"}[tee] {
					t.Fatal("wrong attribution")
				}
				if _, err = c.VerifyResponse(context.Background(), result.DecisionID); err != nil || f.f.signatureCalls.Load() != 1 {
					t.Fatal("receipt verification not memoized", err)
				}
				if tee {
					_, err = c.CreateChatCompletion(context.Background(), chatRequest())
					requireCode(t, err, "e2ee.model_public_key_required")
					if f.f.chats.Load() != 0 {
						t.Fatal("System One session reused for Chat")
					}
				}
			})
		}
	}
}
func TestSystemOneFailuresAndUnsupportedRequests(t *testing.T) {
	for _, mode := range []string{"429", "invalid", "id", "tamper", "signer", "bad-model", "e2ee", "ohttp", "stream", "direct"} {
		t.Run(mode, func(t *testing.T) {
			c, f := systemOneClient(t, true, Ed25519, func(f *systemOneCloud, o *InferenceOptions) {
				switch mode {
				case "429":
					f.status = 429
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
			if mode == "direct" {
				c.api.direct = true
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
			want := int32(1)
			if mode == "bad-model" || mode == "e2ee" || mode == "ohttp" || mode == "stream" || mode == "direct" {
				want = 0
			}
			if f.calls.Load() != want {
				t.Fatalf("sent %d requests, want %d", f.calls.Load(), want)
			}
		})
	}
}
func TestSystemOneUsesResponseCacheBoundsAndCancellation(t *testing.T) {
	c, _ := systemOneClient(t, false, Ed25519, func(_ *systemOneCloud, o *InferenceOptions) { o.MaxReceiptCacheBytes = 10 })
	_, err := c.CreateSystemOne(context.Background(), systemOneRequest())
	requireCode(t, err, "api.body_too_large")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.CreateSystemOne(ctx, systemOneRequest())
	if err != context.Canceled {
		t.Fatal(err)
	}
	_ = c.Close()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = c.CreateSystemOne(ctx, systemOneRequest())
	requireCode(t, err, "api.client_closed")
}

func TestSystemOneRetainsEveryReportSharingReceiptSigner(t *testing.T) {
	for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
		t.Run(string(algo), func(t *testing.T) {
			client, fixture := systemOneClient(t, true, algo, func(f *systemOneCloud, _ *InferenceOptions) { f.sharedSigner = true })
			decision, err := client.CreateSystemOne(context.Background(), systemOneRequest())
			if err != nil {
				t.Fatal(err)
			}
			verified, err := client.VerifyResponse(context.Background(), decision.DecisionID)
			if err != nil {
				t.Fatal(err)
			}
			if len(verified.Attestations) != 2 {
				t.Fatalf("expected two matching reports, got %d", len(verified.Attestations))
			}
			for _, report := range verified.Attestations {
				if report.Signer != verified.Signature.Signer {
					t.Fatal("retained unrelated signer")
				}
			}
			if fixture.calls.Load() != 1 {
				t.Fatal("replayed decision")
			}
		})
	}
}
