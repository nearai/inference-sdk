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
	"os"
	"strings"
	"sync"
	"testing"

	// "github.com/anthropics/anthropic-sdk-go/v2"
	// anthropicoption "github.com/anthropics/anthropic-sdk-go/v2/option"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	nearai "github.com/nearai/inference-sdk/go"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/responses"
	"golang.org/x/crypto/sha3"
)

// Exercise the official SDK's JSON and SSE consumption, including its early
// [DONE] handling, against the real verified transport and signed wire bytes.
func TestOpenAIClientIntegration(t *testing.T) {
	for _, direct := range []bool{false, true} {
		name := "gateway"
		if direct {
			name = "direct"
		}
		t.Run(name, func(t *testing.T) { testOpenAIClientIntegration(t, direct, "chat", nearai.Ed25519) })
	}
}

func testOpenAIClientIntegration(t *testing.T, direct bool, protocol string, algo nearai.SigningAlgo) {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	address := hex.EncodeToString(pub)
	binding := []byte(pub)
	publicKey := address
	sign := func(text string) string { return hex.EncodeToString(ed25519.Sign(priv, []byte(text))) }
	if algo == nearai.ECDSA {
		key, err := secp.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		public := key.PubKey().SerializeUncompressed()[1:]
		keccak := func(data []byte) []byte { h := sha3.NewLegacyKeccak256(); h.Write(data); return h.Sum(nil) }
		address = hex.EncodeToString(keccak(public)[12:])
		publicKey = hex.EncodeToString(public)
		binding = make([]byte, 32)
		decoded, _ := hex.DecodeString(address)
		copy(binding, decoded)
		sign = func(text string) string {
			digest := keccak([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(text), text)))
			compact := secpecdsa.SignCompact(key, digest, false)
			return hex.EncodeToString(append(compact[1:], compact[0]))
		}
	}
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
			data := append(append([]byte(nil), binding...), nb...)
			quote, _ := json.Marshal(nearai.QuoteVerificationResult{TCBStatus: "UpToDate", ReportData: data, MRConfigID: mr, RTMR3: rtmr[:]})
			report := map[string]any{
				"request_nonce":   n,
				"signing_algo":    algo,
				"signing_address": address,
				"intel_quote":     string(quote),
				"report_data":     hex.EncodeToString(data),
				"event_log":       []any{map[string]any{"imr": 3, "digest": hex.EncodeToString(digest[:])}},
				"info":            map[string]any{"tcb_info": map[string]any{"app_compose": compose}},
			}
			if direct {
				if r.URL.Query().Get("include_tls_fingerprint") != "false" {
					t.Error("direct TLS attestation must remain disabled")
				}
				report["model_name"] = "model"
				report["signing_public_key"] = publicKey
				response := map[string]any{}
				for key, value := range report {
					response[key] = value
				}
				response["all_attestations"] = []any{report}
				json.NewEncoder(w).Encode(response)
			} else {
				json.NewEncoder(w).Encode(map[string]any{"gateway_attestation": report})
			}
		case strings.HasSuffix(r.URL.Path, "/chat/completions"), strings.HasSuffix(r.URL.Path, "/messages"), strings.HasSuffix(r.URL.Path, "/responses"):
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
			if protocol != "chat" {
				name := "message"
				if protocol == "responses" {
					name = "response"
				}
				suffix := ".json"
				if parsed.Stream {
					suffix = ".sse"
				}
				raw, err := os.ReadFile("../../test-fixtures/" + protocol + "/" + name + suffix)
				if err != nil {
					t.Error(err)
					return
				}
				reply = strings.ReplaceAll(string(raw), map[string]string{"messages": "msg_fixture", "responses": "resp_fixture"}[protocol], id)
			}

			reqHash, resHash := sha256.Sum256(body), sha256.Sum256([]byte(reply))
			text := fmt.Sprintf("%x:%x", reqHash, resHash)
			kind := "gateway"
			if direct {
				kind = "provider_tee"
				text = "model:" + text
			}
			sig := map[string]any{
				"signature_kind":  kind,
				"signing_algo":    algo,
				"signing_address": address,
				"signature":       sign(text),
				"text":            text,
			}
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
	quoteVerifier := func(_ context.Context, raw string) (nearai.QuoteVerificationResult, error) {
		var q nearai.QuoteVerificationResult
		err := json.Unmarshal([]byte(raw), &q)
		return q, err
	}
	opts := nearai.InferenceOptions{
		ClientOptions:       nearai.ClientOptions{APIKey: "key", BaseURL: server.URL + "/v1"},
		DisableTLSBinding:   true,
		SigningAlgo:         algo,
		GatewayVerification: nearai.VerificationOptions{QuoteVerifier: quoteVerifier},
		ModelVerification:   nearai.VerificationOptions{QuoteVerifier: quoteVerifier},
	}
	var c *nearai.InferenceClient
	if direct {
		// These adapter fixtures are plaintext; E2EE has dedicated SDK coverage.
		c, e = nearai.NewDirectInferenceClient(nearai.DirectInferenceOptions{
			InferenceOptions: opts,
		})
	} else {
		c, e = nearai.NewInferenceClient(opts)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	/* Messages support is deferred until a later release.
	if protocol == "messages" {
		api := anthropic.NewClient(anthropicoption.WithAPIKey("key"), anthropicoption.WithBaseURL(server.URL), anthropicoption.WithHTTPClient(c.HTTPClient()), anthropicoption.WithMaxRetries(0))
		params := anthropic.MessageNewParams{Model: "model", MaxTokens: 128, Messages: []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock("Hello"))}}
		message, err := api.Messages.New(t.Context(), params)
		if err != nil {
			t.Fatal(err)
		}
		if message.ID != "json" || len(message.Content) == 0 {
			t.Fatal(message)
		}
		if _, err = c.VerifyResponse(t.Context(), message.ID); err != nil {
			t.Fatal(err)
		}
		stream := api.Messages.NewStreaming(t.Context(), params)
		defer stream.Close()
		var accumulated anthropic.Message
		for stream.Next() {
			if err = accumulated.Accumulate(stream.Current()); err != nil {
				t.Fatal(err)
			}
		}
		if err = stream.Err(); err != nil {
			t.Fatal(err)
		}
		if accumulated.ID != "stream" || len(accumulated.Content) == 0 {
			t.Fatal(accumulated)
		}
		if _, err = c.VerifyResponse(t.Context(), accumulated.ID); err != nil {
			t.Fatal(err)
		}
		return
	}
	*/
	if protocol == "responses" {
		api := openai.NewClient(option.WithAPIKey("key"), option.WithBaseURL(c.BaseURL()), option.WithHTTPClient(c.HTTPClient()), option.WithMaxRetries(0))
		params := responses.ResponseNewParams{Model: "model", Input: responses.ResponseNewParamsInputUnion{OfString: openai.String("Hello")}, Store: openai.Bool(false)}
		response, err := api.Responses.New(t.Context(), params)
		if err != nil {
			t.Fatal(err)
		}
		if response.ID != "json" || response.OutputText() == "" {
			t.Fatal(response)
		}
		if _, err = c.VerifyResponse(t.Context(), response.ID); err != nil {
			t.Fatal(err)
		}
		stream := api.Responses.NewStreaming(t.Context(), params)
		defer stream.Close()
		id, text := "", ""
		for stream.Next() {
			event := stream.Current()
			if event.Type == "response.created" {
				id = event.Response.ID
			}
			if event.Type == "response.output_text.delta" {
				text += event.Delta
			}
		}
		if err = stream.Err(); err != nil {
			t.Fatal(err)
		}
		if id != "stream" || text == "" {
			t.Fatal("incomplete stream", id, text)
		}
		if _, err = c.VerifyResponse(t.Context(), id); err != nil {
			t.Fatal(err)
		}
		return
	}

	ai := openai.NewClient(option.WithAPIKey("key"), option.WithBaseURL(c.BaseURL()), option.WithHTTPClient(c.HTTPClient()), option.WithMaxRetries(0))
	params := openai.ChatCompletionNewParams{
		Model:    "model",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Hello")},
	}
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

func TestOfficialGatewayEndpoints(t *testing.T) {
	for _, protocol := range []string{ /* "messages", */ "responses"} {
		for _, algo := range []nearai.SigningAlgo{nearai.Ed25519, nearai.ECDSA} {
			t.Run(protocol+"/"+string(algo), func(t *testing.T) { testOpenAIClientIntegration(t, false, protocol, algo) })
		}
	}
}
