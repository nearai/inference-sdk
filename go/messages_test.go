package nearai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
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
	sig := f.cloud.completionSignature(body, f.raw, f.provider)
	f.cloud.mu.Lock()
	f.cloud.signatures["msg_fixture"] = sig
	f.cloud.mu.Unlock()
	visible := f.raw
	if f.tamper {
		visible = bytes.ReplaceAll(visible, []byte("Hello"), []byte("Altered"))
	}
	writeChunkedResponse(w, visible, f.streaming, f.status)
}

func messageInput(streaming bool) map[string]any {
	return map[string]any{"model": "canonical/model", "max_tokens": 128, "stream": streaming, "messages": []any{
		map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "prior", "name": "weather", "input": map[string]any{}}}},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "prior", "content": "20"}}},
	}}
}
func messagesClient(t *testing.T, streaming bool, modify func(*InferenceOptions)) (*InferenceClient, *messagesFixture) {
	t.Helper()
	path := "../test-fixtures/messages/message.json"
	if streaming {
		path = "../test-fixtures/messages/message.sse"
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	cloud := newFakeCloud(t)
	cloud.tee = true
	f := &messagesFixture{cloud: cloud, raw: raw, streaming: streaming}
	c, _ := fakeClient(t, f, modify)
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
	for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
		for _, streaming := range []bool{false, true} {
			t.Run(string(algo)+"/"+map[bool]string{false: "json", true: "sse"}[streaming], func(t *testing.T) {
				c, f := messagesClient(t, streaming, func(o *InferenceOptions) { o.SigningAlgo = algo })
				if algo == ECDSA {
					f.cloud.useECDSA()
				}
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
				if receipt.SignatureKind != "gateway" || receipt.Signature.SignedText == "" || receipt.Signature.Signer.SigningAlgo != algo {
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
	direct, e := NewDirectInferenceClient(DirectInferenceOptions{ClientOptions: c.options.ClientOptions})
	if e != nil {
		t.Fatal(e)
	}
	defer direct.Close()
	req, _ := http.NewRequest("POST", direct.BaseURL()+"messages", strings.NewReader(`{"model":"canonical/model","messages":[]}`))
	_, e = direct.RoundTrip(req)
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

func TestMessagesDuplicateIDPreservesOriginalReceipt(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			client, fixture := messagesClient(t, streaming, nil)
			if _, err := sendMessage(t, client, streaming); err != nil {
				t.Fatal(err)
			}
			original, err := client.VerifyResponse(context.Background(), "msg_fixture")
			if err != nil {
				t.Fatal(err)
			}
			_, err = sendMessage(t, client, streaming)
			requireCode(t, err, "api.duplicate_completion_id")
			verified, err := client.VerifyResponse(context.Background(), "msg_fixture")
			if err != nil || verified.ID != original.ID {
				t.Fatal(verified, err)
			}
			if fixture.cloud.signatureCalls.Load() != 1 || fixture.cloud.chats.Load() != 2 {
				t.Fatal("duplicate ID replaced the original receipt")
			}
		})
	}
}

// Exercise signed fixtures through the public transport and receipt API.
func TestMessagesStreamContract(t *testing.T) {
	raw, err := os.ReadFile("../test-fixtures/messages/streams.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Body string
		Valid      bool
	}
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range cases {
		t.Run(scenario.Name, func(t *testing.T) {
			client, fixture := messagesClient(t, true, nil)
			fixture.raw = []byte(scenario.Body)
			body, err := sendMessage(t, client, true)
			if scenario.Valid {
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(body, fixture.raw) {
					t.Fatal("response bytes changed")
				}
				if _, err = client.VerifyResponse(context.Background(), "msg_fixture"); err != nil {
					t.Fatal(err)
				}
			} else {
				requireCode(t, err, "api.invalid_response")
				_, err = client.VerifyResponse(context.Background(), "msg_fixture")
				requireCode(t, err, "api.completion_not_found")
				if fixture.cloud.signatureCalls.Load() != 0 {
					t.Fatal("invalid stream fetched a receipt")
				}
			}
			if fixture.cloud.chats.Load() != 1 {
				t.Fatal("inference replayed")
			}
		})
	}
}

func TestMessagesZeroResponseTTL(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			client, fixture := messagesClient(t, streaming, func(o *InferenceOptions) {
				zero := time.Duration(0)
				o.ResponseTTL = &zero
			})
			for range 2 {
				if _, err := sendMessage(t, client, streaming); err != nil {
					t.Fatal(err)
				}
				_, err := client.VerifyResponse(context.Background(), "msg_fixture")
				requireCode(t, err, "api.completion_not_found")
			}
			if fixture.cloud.signatureCalls.Load() != 0 {
				t.Fatal("zero TTL fetched a receipt")
			}
		})
	}
}
