//go:build e2e

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"example.com/nearai-inference-example/internal/demo"
	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
	nearai "github.com/nearai/inference-sdk/go"
)

func TestLiveAnthropic(t *testing.T) {
	for _, name := range []string{"NEARAI_API_KEY", "NEARAI_BASE_URL", "NEARAI_E2E_MODELS"} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is required", name)
		}
	}
	var models []struct{ ID, Endpoint string }
	if err := json.Unmarshal([]byte(os.Getenv("NEARAI_E2E_MODELS")), &models); err != nil {
		t.Fatal(err)
	}
	var selected []string
	for _, model := range models {
		if model.Endpoint == "messages" {
			selected = append(selected, model.ID)
		}
	}
	if len(selected) != 1 || selected[0] == "" {
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
			inference, err := nearai.NewInferenceClient(nearai.InferenceOptions{
				ClientOptions: nearai.ClientOptions{APIKey: os.Getenv("NEARAI_API_KEY"), BaseURL: os.Getenv("NEARAI_BASE_URL")},
				SigningAlgo:   scenario.algo, OHTTP: scenario.ohttp,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer inference.Close()
			client := anthropic.NewClient(
				option.WithAPIKey(os.Getenv("NEARAI_API_KEY")),
				option.WithBaseURL(strings.TrimSuffix(inference.BaseURL(), "v1/")),
				option.WithHTTPClient(inference.HTTPClient()),
				option.WithHeader("anthropic-version", "2023-06-01"),
				option.WithMaxRetries(0),
			)
			request := anthropic.MessageNewParams{
				Model: anthropic.Model(selected[0]), MaxTokens: 128,
				Messages: []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock("Reply with the word OK."))},
			}
			for _, streaming := range []bool{false, true} {
				var message anthropic.Message
				if streaming {
					stream := client.Messages.NewStreaming(ctx, request)
					defer stream.Close()
					stopped := false
					for stream.Next() {
						event := stream.Current()
						if event.Type == "message_stop" {
							stopped = true
						}
						if err := message.Accumulate(event); err != nil {
							t.Fatal(err)
						}
					}
					if err := stream.Err(); err != nil {
						t.Fatal(err)
					}
					if err := stream.Close(); err != nil {
						t.Fatal(err)
					}
					if !stopped {
						t.Fatal("SSE must reach message_stop and EOF")
					}
				} else {
					result, err := client.Messages.New(ctx, request)
					if err != nil {
						t.Fatal(err)
					}
					message = *result
				}
				text := ""
				for _, block := range message.Content {
					if block.Type == "text" {
						text += block.Text
					}
				}
				if message.ID == "" || message.Type != "message" || message.StopReason != "end_turn" || strings.TrimSpace(text) == "" {
					t.Fatal("expected a nonempty complete Messages answer")
				}
				receiptCtx, receiptCancel := context.WithTimeout(ctx, 15*time.Second)
				err = demo.Retry(receiptCtx, func() error {
					receipt, err := inference.VerifyResponse(receiptCtx, message.ID)
					if err == nil && (receipt.ID != message.ID || receipt.SignatureKind != "gateway") {
						t.Fatal("expected matching Gateway receipt")
					}
					return err
				})
				receiptCancel()
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("Official Anthropic model=%s, stream=%t: verified Gateway receipt", selected[0], streaming)
			}
		})
	}
}
