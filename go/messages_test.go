package nearai

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type messagesFixture struct {
	cloud                       *fakeCloud
	raw                         []byte
	streaming, tamper, provider bool
	status                      int
}

func (f *messagesFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/messages" {
		f.cloud.ServeHTTP(w, r)
		return
	}
	f.cloud.chats.Add(1)
	if f.cloud.attestations.Load() == 0 {
		f.cloud.t.Error("request sent before preflight")
	}
	if r.Header.Get("Authorization") != "Bearer test" || r.Header.Get(NoAliasingHeader) != "true" || r.Header.Get("X-Client-Pub-Key") != "" || r.Header.Get("X-Model-Pub-Key") != "" || r.Header.Get("Anthropic-Version") == "" || r.Header.Get("X-Api-Key") != "" {
		f.cloud.t.Error("incorrect inference headers")
	}
	body, _ := io.ReadAll(r.Body)
	var request map[string]any
	json.Unmarshal(body, &request)
	items := request["messages"].([]any)
	if items[1].(map[string]any)["role"] != "user" {
		f.cloud.t.Error("replay input not preserved")
	}
	kind := "gateway"
	text := hashText(body) + ":" + hashText(f.raw)
	if f.provider {
		kind = "provider_tee"
		text = "canonical/model:" + text
	}
	sig := CompletionSignature{kind, text, hex.EncodeToString(ed25519.Sign(f.cloud.priv, []byte(text))), f.cloud.a.Signer}
	f.cloud.mu.Lock()
	f.cloud.signatures["msg_fixture"] = sig
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

func messageInput(streaming bool) map[string]any {
	return map[string]any{"model": "canonical/model", "max_tokens": 128, "stream": streaming, "messages": []any{
		map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "prior", "name": "weather", "input": map[string]any{}}}},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "prior", "content": "20"}}},
	}}
}
func messagesClient(t *testing.T, streaming bool, modify func(*InferenceOptions)) (*InferenceClient, *messagesFixture) {
	t.Helper()
	path := "testdata/messages/message.json"
	if streaming {
		path = "testdata/messages/message.sse"
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	cloud := newFakeCloud(t)
	cloud.tee = true
	f := &messagesFixture{cloud: cloud, raw: raw, streaming: streaming}
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
func sendMessage(t *testing.T, c *InferenceClient, streaming bool) ([]byte, error) {
	t.Helper()
	if !streaming {
		return c.CreateMessage(context.Background(), messageInput(false))
	}
	body, _ := json.Marshal(messageInput(true))
	req, _ := http.NewRequest("POST", c.BaseURL()+"messages", bytes.NewReader(body))
	res, e := c.HTTPClient().Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)
}
func TestMessagesExactGatewayReceipts(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{false: "json", true: "sse"}[streaming], func(t *testing.T) {
			c, f := messagesClient(t, streaming, nil)
			body, e := sendMessage(t, c, streaming)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(body, f.raw) {
				t.Fatal("message bytes changed")
			}
			receipt, e := c.VerifyResponse(context.Background(), "msg_fixture")
			if e != nil {
				t.Fatal(e)
			}
			if receipt.SignatureKind != "gateway" || receipt.Signature.SignedText == "" {
				t.Fatal("wrong receipt")
			}
			_, e = c.VerifyResponse(context.Background(), "toolu_fixture")
			requireCode(t, e, "api.completion_not_found")
			if f.cloud.chats.Load() != 1 {
				t.Fatal("inference repeated")
			}
		})
	}
}
func TestMessagesTamperingAndProviderReceipts(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, provider := range []bool{false, true} {
			c, f := messagesClient(t, streaming, nil)
			f.provider = provider
			f.tamper = !provider
			if _, e := sendMessage(t, c, streaming); e != nil {
				t.Fatal(e)
			}
			_, e := c.VerifyResponse(context.Background(), "msg_fixture")
			code := "signature.payload_mismatch"
			if provider {
				code = "signature.kind_mismatch"
			}
			requireCode(t, e, code)
		}
	}
}
func TestMessagesRetrySignatureOnly(t *testing.T) {
	c, f := messagesClient(t, false, nil)
	if _, e := sendMessage(t, c, false); e != nil {
		t.Fatal(e)
	}
	f.cloud.signatureStatus.Store(503)
	_, e := c.VerifyResponse(context.Background(), "msg_fixture")
	requireCode(t, e, "api.http_status")
	f.cloud.signatureStatus.Store(0)
	if _, e = c.VerifyResponse(context.Background(), "msg_fixture"); e != nil {
		t.Fatal(e)
	}
	if f.cloud.chats.Load() != 1 || f.cloud.signatureCalls.Load() != 2 {
		t.Fatal("incorrect retry scope")
	}
}
func TestMessagesMissingIDsAndHTTPErrors(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		c, f := messagesClient(t, streaming, nil)
		f.raw = []byte(`{"output":[]}`)
		if streaming {
			f.raw = []byte("data: {\"id\":\"item-only\",\"item\":{\"id\":\"msg_1\"}}\n\n")
		}
		_, e := sendMessage(t, c, streaming)
		requireCode(t, e, "api.invalid_response")
	}
	c, f := messagesClient(t, false, nil)
	f.status = 400
	_, e := sendMessage(t, c, false)
	requireCode(t, e, "api.http_status")
	_, e = c.VerifyResponse(context.Background(), "msg_fixture")
	requireCode(t, e, "api.completion_not_found")
}
func TestMessagesRejectUnsupportedBeforeIO(t *testing.T) {
	c, f := messagesClient(t, false, func(o *InferenceOptions) { o.E2EE = true })
	_, e := sendMessage(t, c, false)
	requireCode(t, e, "api.invalid_input")
	if f.cloud.attestations.Load() != 0 {
		t.Fatal("E2EE triggered I/O")
	}
	c, f = messagesClient(t, false, nil)
	_, e = c.CreateMessage(context.Background(), messageInput(true))
	requireCode(t, e, "api.invalid_input")
	for _, path := range []string{c.BaseURL() + "messages/msg_fixture", "https://other.test/v1/messages"} {
		req, _ := http.NewRequest("POST", path, strings.NewReader(`{"model":"canonical/model","input":"Hi"}`))
		_, e = c.RoundTrip(req)
		requireCode(t, e, "api.invalid_input")
	}
	direct, e := NewDirectInferenceClient(DirectInferenceOptions{InferenceOptions: c.options})
	if e != nil {
		t.Fatal(e)
	}
	defer direct.Close()
	_, e = direct.CreateMessage(context.Background(), messageInput(false))
	requireCode(t, e, "api.invalid_input")
	if f.cloud.attestations.Load() != 0 {
		t.Fatal("unsupported endpoint triggered I/O")
	}
}

func TestMessagesIncompleteOrFailedStreams(t *testing.T) {
	for _, ending := range []string{
		"",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}",
		"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"other\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	} {
		c, f := messagesClient(t, true, nil)
		f.raw = []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_fixture\"}}\n\n" + ending)
		_, err := sendMessage(t, c, true)
		requireCode(t, err, "api.invalid_response")
		_, err = c.VerifyResponse(context.Background(), "msg_fixture")
		requireCode(t, err, "api.completion_not_found")
		if f.cloud.chats.Load() != 1 || f.cloud.signatureCalls.Load() != 0 {
			t.Fatal("unexpected replay or receipt lookup")
		}
	}
}

func TestMessagesCloseBeforeCompletion(t *testing.T) {
	c, f := messagesClient(t, true, nil)
	body, _ := json.Marshal(messageInput(true))
	req, _ := http.NewRequest("POST", c.BaseURL()+"messages", bytes.NewReader(body))
	res, err := c.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	if _, err = res.Body.Read(one); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	_, err = c.VerifyResponse(context.Background(), "msg_fixture")
	requireCode(t, err, "api.completion_not_found")
	if f.cloud.chats.Load() != 1 {
		t.Fatal("inference replayed")
	}
}
