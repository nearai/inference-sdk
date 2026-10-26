package nearai

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type responsesFixture struct {
	cloud                       *fakeCloud
	ecdsaKey                    *secp.PrivateKey
	raw                         []byte
	streaming, tamper, provider bool
	status                      int
}

func (f *responsesFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/responses" {
		f.cloud.ServeHTTP(w, r)
		return
	}
	f.cloud.chats.Add(1)
	if f.cloud.attestations.Load() == 0 {
		f.cloud.t.Error("request sent before preflight")
	}
	if r.Header.Get("Authorization") != "Bearer test" || r.Header.Get(NoAliasingHeader) != "true" || r.Header.Get("X-Client-Pub-Key") != "" {
		f.cloud.t.Error("incorrect inference headers")
	}
	body, _ := io.ReadAll(r.Body)
	var request map[string]any
	json.Unmarshal(body, &request)
	items := request["input"].([]any)
	if items[1].(map[string]any)["type"] != "function_call_output" {
		f.cloud.t.Error("replay input not preserved")
	}
	kind := "gateway"
	text := hashText(body) + ":" + hashText(f.raw)
	if f.provider {
		kind = "provider_tee"
		text = "canonical/model:" + text
	}
	sig := CompletionSignature{kind, text, hex.EncodeToString(ed25519.Sign(f.cloud.priv, []byte(text))), f.cloud.a.Signer}
	if f.ecdsaKey != nil {
		digest := keccak([]byte("\x19Ethereum Signed Message:\n" + itoa(len(text)) + text))
		compact := secpecdsa.SignCompact(f.ecdsaKey, digest, false)
		sig.Signature = hex.EncodeToString(append(compact[1:], compact[0]))
	}
	f.cloud.mu.Lock()
	f.cloud.signatures["resp_fixture"] = sig
	f.cloud.mu.Unlock()
	contentType := "application/json"
	if f.streaming {
		contentType = "text/event-stream"
	}
	w.Header().Set("Content-Type", contentType)
	if f.status != 0 {
		w.WriteHeader(f.status)
	}
	visible := f.raw
	if f.tamper {
		visible = bytes.ReplaceAll(visible, []byte("你好"), []byte("篡改"))
	}
	for i := 0; i < len(visible); i += 7 {
		end := min(i+7, len(visible))
		w.Write(visible[i:end])
		w.(http.Flusher).Flush()
	}
}

func responseInput(streaming bool) map[string]any {
	return map[string]any{"model": "canonical/model", "store": false, "stream": streaming, "input": []any{
		map[string]any{"type": "function_call", "call_id": "prior", "name": "weather", "arguments": "{}"},
		map[string]any{"type": "function_call_output", "call_id": "prior", "output": "{\"temperature\":20}"},
	}}
}
func responsesClient(t *testing.T, streaming bool, modify func(*InferenceOptions)) (*InferenceClient, *responsesFixture) {
	t.Helper()
	path := "testdata/responses/response.json"
	if streaming {
		path = "testdata/responses/response.sse"
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	cloud := newFakeCloud(t)
	cloud.tee = true
	f := &responsesFixture{cloud: cloud, raw: raw, streaming: streaming}
	server := httptest.NewServer(f)
	options := InferenceOptions{ClientOptions: ClientOptions{APIKey: "test", BaseURL: server.URL + "/v1"}, DisableTLSBinding: true, GatewayVerification: VerificationOptions{QuoteVerifier: fakeQuote}, ModelVerification: VerificationOptions{QuoteVerifier: fakeQuote}}
	if modify != nil {
		modify(&options)
	}
	c, e := NewInferenceClient(options)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close(); server.Close() })
	return c, f
}
func sendResponse(t *testing.T, c *InferenceClient, streaming bool) ([]byte, error) {
	t.Helper()
	if !streaming {
		return c.CreateResponse(context.Background(), responseInput(false))
	}
	body, _ := json.Marshal(responseInput(true))
	req, _ := http.NewRequest("POST", c.BaseURL()+"responses", bytes.NewReader(body))
	res, e := c.HTTPClient().Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)
}
func TestResponsesExactGatewayReceipts(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{false: "json", true: "sse"}[streaming], func(t *testing.T) {
			c, f := responsesClient(t, streaming, nil)
			body, e := sendResponse(t, c, streaming)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(body, f.raw) {
				t.Fatal("response bytes changed")
			}
			receipt, e := c.VerifyResponse(context.Background(), "resp_fixture")
			if e != nil {
				t.Fatal(e)
			}
			if receipt.SignatureKind != "gateway" || receipt.Signature.SignedText == "" {
				t.Fatal("wrong receipt")
			}
			_, e = c.VerifyResponse(context.Background(), "msg_1")
			requireCode(t, e, "api.completion_not_found")
			if f.cloud.chats.Load() != 1 {
				t.Fatal("inference repeated")
			}
		})
	}
}
func TestResponsesTamperingAndProviderReceipts(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, provider := range []bool{false, true} {
			c, f := responsesClient(t, streaming, nil)
			f.provider = provider
			f.tamper = !provider
			if _, e := sendResponse(t, c, streaming); e != nil {
				t.Fatal(e)
			}
			_, e := c.VerifyResponse(context.Background(), "resp_fixture")
			code := "signature.payload_mismatch"
			if provider {
				code = "signature.kind_mismatch"
			}
			requireCode(t, e, code)
		}
	}
}
func TestResponsesRetrySignatureOnly(t *testing.T) {
	c, f := responsesClient(t, false, nil)
	if _, e := sendResponse(t, c, false); e != nil {
		t.Fatal(e)
	}
	f.cloud.signatureStatus.Store(503)
	_, e := c.VerifyResponse(context.Background(), "resp_fixture")
	requireCode(t, e, "api.http_status")
	f.cloud.signatureStatus.Store(0)
	if _, e = c.VerifyResponse(context.Background(), "resp_fixture"); e != nil {
		t.Fatal(e)
	}
	if f.cloud.chats.Load() != 1 || f.cloud.signatureCalls.Load() != 2 {
		t.Fatal("incorrect retry scope")
	}
}
func TestResponsesMissingIDsAndHTTPErrors(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		c, f := responsesClient(t, streaming, nil)
		f.raw = []byte(`{"output":[]}`)
		if streaming {
			f.raw = []byte("data: {\"id\":\"item-only\",\"item\":{\"id\":\"msg_1\"}}\n\n")
		}
		_, e := sendResponse(t, c, streaming)
		requireCode(t, e, "api.invalid_response")
	}
	c, f := responsesClient(t, false, nil)
	f.status = 400
	_, e := sendResponse(t, c, false)
	requireCode(t, e, "api.http_status")
	_, e = c.VerifyResponse(context.Background(), "resp_fixture")
	requireCode(t, e, "api.completion_not_found")
}
func TestResponsesRejectUnsupportedBeforeIO(t *testing.T) {
	c, f := responsesClient(t, false, func(o *InferenceOptions) { o.E2EE = true })
	_, e := sendResponse(t, c, false)
	requireCode(t, e, "api.invalid_input")
	if f.cloud.attestations.Load() != 0 {
		t.Fatal("E2EE triggered I/O")
	}
	c, f = responsesClient(t, false, nil)
	_, e = c.CreateResponse(context.Background(), responseInput(true))
	requireCode(t, e, "api.invalid_input")
	for _, path := range []string{c.BaseURL() + "responses/resp_fixture", "https://other.test/v1/responses"} {
		req, _ := http.NewRequest("POST", path, strings.NewReader(`{"model":"canonical/model","input":"Hi"}`))
		_, e = c.RoundTrip(req)
		requireCode(t, e, "api.invalid_input")
	}
	direct, e := NewDirectInferenceClient(DirectInferenceOptions{InferenceOptions: c.options})
	if e != nil {
		t.Fatal(e)
	}
	defer direct.Close()
	_, e = direct.CreateResponse(context.Background(), responseInput(false))
	requireCode(t, e, "api.invalid_input")
	if f.cloud.attestations.Load() != 0 {
		t.Fatal("unsupported endpoint triggered I/O")
	}
}

func TestResponsesECDSA(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{false: "json", true: "sse"}[streaming], func(t *testing.T) {
			c, f := responsesClient(t, streaming, func(o *InferenceOptions) { o.SigningAlgo = ECDSA })
			key, err := secp.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			f.ecdsaKey = key
			public := key.PubKey().SerializeUncompressed()[1:]
			address := keccak(public)[12:]
			f.cloud.a.Signer = SigningIdentity{ECDSA, hex.EncodeToString(address)}
			f.cloud.a.SigningPublicKey = hex.EncodeToString(public)
			clear(f.cloud.q.ReportData[:32])
			copy(f.cloud.q.ReportData, address)
			raw, err := sendResponse(t, c, streaming)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, f.raw) {
				t.Fatal("response bytes changed")
			}
			receipt, err := c.VerifyResponse(t.Context(), "resp_fixture")
			if err != nil {
				t.Fatal(err)
			}
			if receipt.SignatureKind != "gateway" || receipt.Signature.Signer.SigningAlgo != ECDSA {
				t.Fatal("wrong receipt")
			}
		})
	}
}
