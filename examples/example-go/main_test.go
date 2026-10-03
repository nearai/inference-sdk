package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	nearai "github.com/nearai/inference-sdk/go"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

// Exercise the official SDK's JSON and SSE consumption, including its early
// [DONE] handling, against the real verified transport and signed wire bytes.
func TestOpenAIClientIntegration(t *testing.T) {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	address := hex.EncodeToString(pub)
	compose := `{}`
	hash := sha256.Sum256([]byte(compose))
	mr := make([]byte, 48)
	mr[0] = 1
	copy(mr[1:], hash[:])
	digest := sha512.Sum384([]byte("fixture"))
	rtmr := sha512.Sum384(append(make([]byte, 48), digest[:]...))
	var mu sync.Mutex
	signatures := map[string]map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/model/"):
			io.WriteString(w, `{"metadata":{"providerType":"proxy","attestationSupported":false}}`)
		case strings.HasSuffix(r.URL.Path, "/attestation/report"):
			n := r.URL.Query().Get("nonce")
			nb, _ := hex.DecodeString(n)
			data := append(append([]byte(nil), pub...), nb...)
			quote, _ := json.Marshal(nearai.QuoteVerificationResult{TCBStatus: "UpToDate", ReportData: data, MRConfigID: mr, RTMR3: rtmr[:]})
			json.NewEncoder(w).Encode(map[string]any{"gateway_attestation": map[string]any{"request_nonce": n, "signing_algo": "ed25519", "signing_address": address, "intel_quote": string(quote), "report_data": hex.EncodeToString(data), "event_log": []any{map[string]any{"imr": 3, "digest": hex.EncodeToString(digest[:])}}, "info": map[string]any{"tcb_info": map[string]any{"app_compose": compose}}}})
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			body, _ := io.ReadAll(r.Body)
			var parsed struct {
				Stream bool `json:"stream"`
			}
			json.Unmarshal(body, &parsed)
			id := "json"
			reply := `{"id":"json","object":"chat.completion","created":1,"model":"model","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"answer"}}]}`
			w.Header().Set("Content-Type", "application/json")
			if parsed.Stream {
				id = "stream"
				w.Header().Set("Content-Type", "text/event-stream")
				reply = "data: {\"id\":\"stream\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"answer\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n"
			}
			reqHash, resHash := sha256.Sum256(body), sha256.Sum256([]byte(reply))
			text := fmt.Sprintf("%x:%x", reqHash, resHash)
			sig := map[string]any{"signature_kind": "gateway", "signing_algo": "ed25519", "signing_address": address, "signature": hex.EncodeToString(ed25519.Sign(priv, []byte(text))), "text": text}
			mu.Lock()
			signatures[id] = sig
			mu.Unlock()
			io.WriteString(w, reply)
		case strings.Contains(r.URL.Path, "/signature/"):
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			mu.Lock()
			sig := signatures[id]
			mu.Unlock()
			json.NewEncoder(w).Encode(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	c, e := nearai.NewInferenceClient(nearai.InferenceOptions{ClientOptions: nearai.ClientOptions{APIKey: "key", BaseURL: server.URL + "/v1"}, DisableTLSBinding: true, GatewayVerification: nearai.VerificationOptions{QuoteVerifier: func(_ context.Context, raw string) (nearai.QuoteVerificationResult, error) {
		var q nearai.QuoteVerificationResult
		e := json.Unmarshal([]byte(raw), &q)
		return q, e
	}}})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ai := openai.NewClient(option.WithAPIKey("key"), option.WithBaseURL(c.BaseURL()), option.WithHTTPClient(c.HTTPClient()), option.WithMaxRetries(0))
	params := openai.ChatCompletionNewParams{Model: "model", Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Hello")}}
	completion, e := ai.Chat.Completions.New(context.Background(), params)
	if e != nil {
		t.Fatal(e)
	}
	if completion.Choices[0].Message.Content != "answer" {
		t.Fatal(completion)
	}
	if _, e = c.VerifyResponse(context.Background(), completion.ID); e != nil {
		t.Fatal(e)
	}
	stream := ai.Chat.Completions.NewStreaming(context.Background(), params)
	id := ""
	text := ""
	for stream.Next() {
		chunk := stream.Current()
		id = chunk.ID
		for _, choice := range chunk.Choices {
			text += choice.Delta.Content
		}
	}
	if e = stream.Err(); e != nil {
		t.Fatal(e)
	}
	stream.Close()
	if text != "answer" {
		t.Fatal(text)
	}
	if _, e = c.VerifyResponse(context.Background(), id); e != nil {
		t.Fatal(e)
	}
}
