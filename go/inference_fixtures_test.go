package nearai

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/andybalholm/brotli"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type fakeCloud struct {
	authorization    string
	expectedHost     string
	encrypt          bool
	streamBody       string
	encoding         string
	t                *testing.T
	a                Attestation
	q                QuoteVerificationResult
	ohttp            *OHTTPAttestation
	priv             ed25519.PrivateKey
	ecdsaKey         *secp.PrivateKey
	mu               sync.Mutex
	signatureStatus  atomic.Int32
	signatureCalls   atomic.Int32
	unavailable      atomic.Bool
	signatureWait    <-chan struct{}
	signatures       map[string]CompletionSignature
	next             int
	metadata         atomic.Int32
	attestations     atomic.Int32
	modelReports     atomic.Int32
	chats            atomic.Int32
	dropChatAt       int32
	extraModel       bool
	sharedModel      bool
	emptyModels      bool
	gatewayReceipt   bool
	badSharedModel   bool
	missingModelKey  bool
	onlyLastModelKey bool
	tee              bool
	direct           bool
	stream           bool
	tamper           bool
	badModel         bool
	slow             <-chan struct{}
}

func newFakeCloud(t *testing.T) *fakeCloud {
	a, q, key := attestationFixture(t, Ed25519)
	return &fakeCloud{t: t, a: a, q: q, priv: key, signatures: map[string]CompletionSignature{}, authorization: "Bearer test"}
}

func (f *fakeCloud) useECDSA() {
	key, err := secp.GeneratePrivateKey()
	if err != nil {
		f.t.Fatal(err)
	}
	f.ecdsaKey = key
	public := key.PubKey().SerializeUncompressed()[1:]
	address := keccak(public)[12:]
	f.a.Signer = SigningIdentity{ECDSA, hex.EncodeToString(address)}
	f.a.SigningPublicKey = hex.EncodeToString(public)
	clear(f.q.ReportData[:32])
	copy(f.q.ReportData, address)
}

func (f *fakeCloud) sign(text string) string {
	if f.ecdsaKey == nil {
		return hex.EncodeToString(ed25519.Sign(f.priv, []byte(text)))
	}
	digest := keccak([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(text), text)))
	compact := secpecdsa.SignCompact(f.ecdsaKey, digest, false)
	return hex.EncodeToString(append(compact[1:], compact[0]))
}
func (f *fakeCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/chat/completions" && r.Header.Get("Accept-Encoding") != "identity" {
		f.t.Errorf("Chat did not force identity encoding")
	}
	if f.expectedHost != "" && r.Host != f.expectedHost {
		f.t.Errorf("unexpected authority %q", r.Host)
	}
	if strings.HasSuffix(r.URL.Path, "/attestation/report") && (f.direct || !r.URL.Query().Has("model")) {
		for _, name := range []string{"Authorization", "Api-Key", "X-Api-Key"} {
			if r.Header.Get(name) != "" {
				f.t.Errorf("attestation sent %s", name)
			}
		}
	} else if r.Header.Get("Authorization") != f.authorization {
		http.Error(w, "bad auth", 401)
		return
	}
	switch {
	case strings.Contains(r.URL.Path, "/model/"):
		f.metadata.Add(1)
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
			generation := f.modelReports.Add(1)
			if f.missingModelKey {
				delete(a, "signing_public_key")
			}
			items := []any{a}
			if f.sharedModel {
				a["info"].(map[string]any)["instance_id"] = "instance-0"
				other := maps.Clone(a)
				const compose = `{"docker_compose_file":"services: {}","name":"second-instance"}`
				other["info"] = map[string]any{"instance_id": "instance-1", "tcb_info": map[string]any{"app_compose": compose}}
				otherQuote := q
				otherQuote.MRConfigID = bytes.Clone(q.MRConfigID)
				hash := sha256.Sum256([]byte(compose))
				copy(otherQuote.MRConfigID[1:], hash[:])
				otherQuote.DebugEnabled = f.badSharedModel
				otherQuote.AdvisoryIDs = append(slices.Clone(q.AdvisoryIDs), fmt.Sprintf("generation-%d", generation))
				encoded, _ := json.Marshal(otherQuote)
				other["intel_quote"] = string(encoded)
				items = append(items, other)
			}
			if f.extraModel {
				other := maps.Clone(a)
				other["signing_address"] = strings.Repeat("22", 32)
				other["signing_public_key"] = other["signing_address"]
				if f.a.Signer.SigningAlgo == ECDSA {
					key := secp.PrivKeyFromBytes(bytes.Repeat([]byte{0x22}, 32))
					public := key.PubKey().SerializeUncompressed()[1:]
					other["signing_public_key"] = hex.EncodeToString(public)
					other["signing_address"] = hex.EncodeToString(keccak(public)[12:])
				}
				report := append([]byte(nil), q.ReportData...)
				clear(report[:32])
				address, _ := hex.DecodeString(other["signing_address"].(string))
				copy(report, address)
				otherQuote := q
				otherQuote.ReportData = report
				encoded, _ := json.Marshal(otherQuote)
				other["intel_quote"] = string(encoded)
				other["report_data"] = hex.EncodeToString(report)
				if f.sharedModel {
					items = slices.Insert(items, 1, any(other))
				} else {
					items = append([]any{other}, items...)
				}
			}

			if f.badModel {
				bad := map[string]any{}
				for k, v := range a {
					bad[k] = v
				}
				bad["signing_address"] = strings.Repeat("22", 32)
				items = append(items, bad)
			}
			if f.emptyModels {
				items = []any{}
			}
			if f.onlyLastModelKey {
				for _, item := range items[:len(items)-1] {
					delete(item.(map[string]any), "signing_public_key")
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"model_attestations": items})
		} else {
			root := map[string]any{"gateway_attestation": a}
			if f.ohttp != nil {
				root["ohttp_attestation"] = f.ohttp
			}
			json.NewEncoder(w).Encode(root)
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
			if r.Header.Get("X-Signing-Algo") != string(f.a.Signer.SigningAlgo) || r.Header.Get("X-Model-Pub-Key") != f.a.SigningPublicKey {
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
		id := "chat-" + strconv.Itoa(f.next)
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
			if f.ecdsaKey != nil {
				secret = f.ecdsaKey.Serialize()
			}
			aad, err := requestAAD(f.a.Signer.SigningAlgo, r.Header.Get("X-Client-Pub-Key"))
			if err != nil {
				f.t.Fatal(err)
			}
			message, err := decryptTextWithAAD(content, e2eeKey{algo: f.a.Signer.SigningAlgo, secret: secret}, fieldAAD(aad, "messages[].content"))
			if err != nil || message != "review" {
				f.t.Errorf("E2EE request: %q %v", message, err)
			}
			encrypted, err := encryptText("answer", E2EEModelKey{f.a.Signer.SigningAlgo, r.Header.Get("X-Client-Pub-Key")})
			if err != nil {
				f.t.Error(err)
			}
			reply = strings.ReplaceAll(reply, "answer", encrypted)
		}
		if f.streamBody != "" {
			reply = f.streamBody
		}
		sig := f.completionSignature(body, []byte(reply), f.tee && !f.gatewayReceipt)
		f.mu.Lock()
		f.signatures[id] = sig
		f.mu.Unlock()
		if f.tamper {
			reply = strings.ReplaceAll(reply, "answer", "altered")
		}
		writeEncodedResponse(f.t, w, []byte(reply), f.encoding)
	case strings.Contains(r.URL.Path, "/signature/"):
		f.signatureCalls.Add(1)
		if f.signatureWait != nil {
			select {
			case <-f.signatureWait:
			case <-r.Context().Done():
				return
			}
		}
		if f.unavailable.Load() {
			json.NewEncoder(w).Encode(map[string]string{"error_code": "pending", "message": "Try later"})
			return
		}
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

func fakeClient(t *testing.T, handler http.Handler, modify func(*InferenceOptions)) (*InferenceClient, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
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
	t.Cleanup(func() { c.Close() })
	return c, server
}
func chatRequest() map[string]any {
	return map[string]any{"model": "canonical/model", "messages": []any{map[string]any{"role": "user", "content": "review"}}}
}

func writeEncodedResponse(t *testing.T, w http.ResponseWriter, body []byte, encoding string) {
	t.Helper()
	if encoding != "" {
		var compressed bytes.Buffer
		var writer io.WriteCloser
		if encoding == "gzip" {
			writer = gzip.NewWriter(&compressed)
		} else {
			writer = brotli.NewWriter(&compressed)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		body = compressed.Bytes()
		w.Header().Set("Content-Encoding", encoding)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}
	_, _ = w.Write(body)
}

func (f *fakeCloud) completionSignature(request, response []byte, provider bool) CompletionSignature {
	kind := "gateway"
	text := hashText(request) + ":" + hashText(response)
	if provider {
		kind = "provider_tee"
		text = "canonical/model:" + text
	}
	return CompletionSignature{Kind: kind, SignedText: text, Signature: f.sign(text), Signer: f.a.Signer}
}

func writeChunkedResponse(w http.ResponseWriter, body []byte, streaming bool, status int) {
	contentType := "application/json"
	if streaming {
		contentType = "text/event-stream"
	}
	w.Header().Set("Content-Type", contentType)
	if status != 0 {
		w.WriteHeader(status)
	}
	for i := 0; i < len(body); i += 7 {
		w.Write(body[i:min(i+7, len(body))])
		w.(http.Flusher).Flush()
	}
}
