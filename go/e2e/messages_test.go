//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
)

func TestMessagesJSONAndSSE(t *testing.T) {
	selected := selectedModels(t, "messages")
	if len(selected) != 1 {
		t.Fatal("expected one Anthropic Messages model")
	}
	for _, scenario := range []struct {
		algo  nearai.SigningAlgo
		ohttp bool
	}{
		{nearai.Ed25519, false}, {nearai.ECDSA, false}, {nearai.Ed25519, true},
	} {
		t.Run(fmt.Sprintf("algo=%s/ohttp=%t", scenario.algo, scenario.ohttp), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
			defer cancel()
			client, err := nearai.NewInferenceClient(nearai.InferenceOptions{
				ClientOptions: nearai.ClientOptions{APIKey: required(t, "NEARAI_API_KEY"), BaseURL: required(t, "NEARAI_BASE_URL")},
				SigningAlgo:   scenario.algo, OHTTP: scenario.ohttp,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			for _, stream := range []bool{false, true} {
				request := map[string]any{
					"model": selected[0].ID, "max_tokens": 128, "stream": stream,
					"messages": []map[string]string{{"role": "user", "content": "Reply with the word OK."}},
				}
				id, text := "", ""
				if stream {
					body, err := json.Marshal(request)
					if err != nil {
						t.Fatal(err)
					}
					req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BaseURL()+"messages", bytes.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					res, err := client.HTTPClient().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					raw := readResponse(t, res)
					stopped, stopReason := false, ""
					for _, data := range sseData(raw) {
						if data == "[DONE]" {
							continue
						}
						var event struct {
							Type    string
							Message struct{ ID string }
							Delta   struct {
								Type, Text string
								StopReason string `json:"stop_reason"`
							}
						}
						if err := json.Unmarshal([]byte(data), &event); err != nil {
							t.Fatal(err)
						}
						switch event.Type {
						case "message_start":
							id = event.Message.ID
						case "message_stop":
							stopped = true
						case "message_delta":
							stopReason = event.Delta.StopReason
						case "content_block_delta":
							if event.Delta.Type == "text_delta" {
								text += event.Delta.Text
							}
						}
					}
					if !stopped || stopReason != "end_turn" {
						t.Fatal("SSE must reach end_turn, message_stop and EOF")
					}
				} else {
					raw, err := client.CreateMessage(ctx, request)
					if err != nil {
						t.Fatal(err)
					}
					var message struct {
						ID, Type   string
						StopReason string `json:"stop_reason"`
						Content    []struct{ Type, Text string }
					}
					if err := json.Unmarshal(raw, &message); err != nil {
						t.Fatal(err)
					}
					if message.Type != "message" || message.StopReason != "end_turn" {
						t.Fatal("expected a complete Message")
					}
					id = message.ID
					for _, block := range message.Content {
						if block.Type == "text" {
							text += block.Text
						}
					}
				}
				if id == "" || strings.TrimSpace(text) == "" {
					t.Fatal("expected a nonempty complete Messages answer")
				}
				receiptCtx, receiptCancel := context.WithTimeout(ctx, 15*time.Second)
				err = retry(receiptCtx, func() error {
					receipt, err := client.VerifyResponse(receiptCtx, id)
					if err == nil && (receipt.ID != id || receipt.SignatureKind != "gateway" || receipt.Signature.Signer.SigningAlgo != scenario.algo) {
						t.Fatal("expected matching Gateway receipt")
					}
					return err
				})
				receiptCancel()
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("Messages model=%s, stream=%t: verified Gateway receipt", selected[0].ID, stream)
			}
		})
	}
}
