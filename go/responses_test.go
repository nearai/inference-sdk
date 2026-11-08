package nearai

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type responsesFixture struct {
	cloud                       *fakeCloud
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
	sig := f.cloud.completionSignature(body, f.raw, f.provider)
	f.cloud.mu.Lock()
	f.cloud.signatures["resp_fixture"] = sig
	f.cloud.mu.Unlock()
	visible := f.raw
	if f.tamper {
		visible = bytes.ReplaceAll(visible, []byte("Original"), []byte("Tampered"))
	}
	writeChunkedResponse(w, visible, f.streaming, f.status)
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
	c, _ := fakeClient(t, f, modify)
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
func TestResponsesClearResponseCache(t *testing.T) {
	c, _ := responsesClient(t, false, nil)
	for i := 0; i < 2; i++ {
		if _, err := sendResponse(t, c, false); err != nil {
			t.Fatal(err)
		}
		if _, err := c.VerifyResponse(context.Background(), "resp_fixture"); err != nil {
			t.Fatal(err)
		}
		c.ClearResponseCache()
		_, err := c.VerifyResponse(context.Background(), "resp_fixture")
		requireCode(t, err, "api.completion_not_found")
	}
}

func TestResponsesExactGatewayReceipts(t *testing.T) {
	for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
		for _, streaming := range []bool{false, true} {
			t.Run(string(algo)+"/"+map[bool]string{false: "json", true: "sse"}[streaming], func(t *testing.T) {
				c, f := responsesClient(t, streaming, func(o *InferenceOptions) { o.SigningAlgo = algo })
				if algo == ECDSA {
					f.cloud.useECDSA()
				}
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
				if receipt.SignatureKind != "gateway" || receipt.Signature.SignedText == "" || receipt.Signature.Signer.SigningAlgo != algo {
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

func TestResponsesStreamContract(t *testing.T) {
	const start = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_fixture\",\"status\":\"in_progress\"}}\n\n"
	for _, tc := range []struct {
		name, ending string
		valid        bool
	}{
		{"completed at EOF", "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_fixture\",\"status\":\"completed\"}}\n\n", true},
		{"output limit", "event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp_fixture\",\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}\n\n", true},
		{"failed response", "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_fixture\",\"status\":\"failed\",\"error\":{\"code\":\"server_error\",\"message\":\"failed\"}}}\n\n", true},
		{"DONE with trailing bytes", "data: [DONE]\n\ndata: not-json\n\n", true},
		{"conflicting response ID", "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"other\",\"status\":\"completed\"}}\n\n", false},
		{"stream error", "event: error\ndata: {\"type\":\"error\",\"error\":{\"message\":\"failed\"}}\n\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, fixture := responsesClient(t, true, nil)
			fixture.raw = []byte(start + tc.ending)
			body, err := sendResponse(t, client, true)
			if tc.valid {
				if err != nil || !bytes.Equal(body, fixture.raw) {
					t.Fatalf("wire response changed: %s, %v", body, err)
				}
				receipt, err := client.VerifyResponse(context.Background(), "resp_fixture")
				if err != nil || receipt.ID != "resp_fixture" || receipt.SignatureKind != "gateway" {
					t.Fatalf("receipt: %+v, %v", receipt, err)
				}
			} else {
				requireCode(t, err, "api.invalid_response")
				_, err = client.VerifyResponse(context.Background(), "resp_fixture")
				requireCode(t, err, "api.completion_not_found")
				if fixture.cloud.signatureCalls.Load() != 0 {
					t.Fatal("invalid stream fetched a receipt")
				}
			}
			if fixture.cloud.chats.Load() != 1 {
				t.Fatal("stream replayed inference")
			}
			_, err = client.VerifyResponse(context.Background(), "msg_1")
			requireCode(t, err, "api.completion_not_found")
		})
	}
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
	direct, e := NewDirectInferenceClient(DirectInferenceOptions{ClientOptions: c.options.ClientOptions})
	if e != nil {
		t.Fatal(e)
	}
	defer direct.Close()
	req, _ := http.NewRequest("POST", direct.BaseURL()+"responses", strings.NewReader(`{"model":"canonical/model","input":"Hi"}`))
	_, e = direct.RoundTrip(req)
	requireCode(t, e, "api.invalid_input")
	if f.cloud.attestations.Load() != 0 {
		t.Fatal("unsupported endpoint triggered I/O")
	}
}
