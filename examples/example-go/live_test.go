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

	nearai "github.com/nearai/inference-sdk/go"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/responses"
)

type liveModel struct{ ID, Provider, Endpoint string }

func liveModels(t *testing.T, endpoint string) []liveModel {
	t.Helper()
	for _, name := range []string{"NEARAI_API_KEY", "NEARAI_BASE_URL", "NEARAI_E2E_MODELS"} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is required", name)
		}
	}
	var models, selected []liveModel
	if err := json.Unmarshal([]byte(os.Getenv("NEARAI_E2E_MODELS")), &models); err != nil {
		t.Fatal(err)
	}
	for _, model := range models {
		if model.Endpoint == endpoint {
			selected = append(selected, model)
		}
	}
	if len(selected) == 0 {
		t.Fatalf("no %s models", endpoint)
	}
	return selected
}

type liveMode struct {
	algo        nearai.SigningAlgo
	e2ee, ohttp bool
}

func liveOpenAI(t *testing.T, mode liveMode) (*nearai.InferenceClient, openai.Client) {
	t.Helper()
	owner, err := nearai.NewInferenceClient(nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{APIKey: os.Getenv("NEARAI_API_KEY"), BaseURL: os.Getenv("NEARAI_BASE_URL")},
		SigningAlgo:   mode.algo, E2EE: mode.e2ee, OHTTP: mode.ohttp,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	return owner, openai.NewClient(option.WithAPIKey(os.Getenv("NEARAI_API_KEY")), option.WithBaseURL(owner.BaseURL()), option.WithHTTPClient(owner.HTTPClient()), option.WithMaxRetries(0))
}
func verifyLiveReceipt(t *testing.T, ctx context.Context, owner *nearai.InferenceClient, id string, algo nearai.SigningAlgo, gateway bool) {
	t.Helper()
	receiptCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err := retryReceipt(receiptCtx, func() error {
		receipt, err := owner.VerifyResponse(receiptCtx, id)
		if err == nil && (receipt.ID != id || receipt.Signature.Signer.SigningAlgo != algo || (gateway && receipt.SignatureKind != "gateway")) {
			t.Fatal("incorrect receipt identity, algorithm, or kind")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestLiveOpenAIChat(t *testing.T) {
	for _, model := range liveModels(t, "chat") {
		modes := []liveMode{{nearai.Ed25519, false, false}}
		if model.Provider == "near" {
			modes = append(modes, liveMode{nearai.Ed25519, true, false}, liveMode{nearai.ECDSA, true, false}, liveMode{nearai.Ed25519, true, true})
		}
		for _, mode := range modes {
			t.Run(fmt.Sprintf("%s/%s/e2ee=%t/ohttp=%t", model.ID, mode.algo, mode.e2ee, mode.ohttp), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
				defer cancel()
				owner, client := liveOpenAI(t, mode)
				request := openai.ChatCompletionNewParams{Model: model.ID, Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Reply with the single word OK.")}, MaxCompletionTokens: openai.Int(1024)}
				completion, err := client.Chat.Completions.New(ctx, request)
				if err != nil {
					t.Fatal(err)
				}
				if completion.ID == "" || len(completion.Choices) == 0 || completion.Choices[0].FinishReason != "stop" || strings.TrimSpace(completion.Choices[0].Message.Content) == "" {
					t.Fatal("expected complete JSON answer")
				}
				verifyLiveReceipt(t, ctx, owner, completion.ID, mode.algo, model.Provider != "near")
				if model.Provider == "chutes" {
					return
				} // Chutes SSE remains provider-gated.
				stream := client.Chat.Completions.NewStreaming(ctx, request)
				defer stream.Close()
				id, text, finish := "", "", ""
				for stream.Next() {
					chunk := stream.Current()
					if id != "" && id != chunk.ID {
						t.Fatal("conflicting completion IDs")
					}
					id = chunk.ID
					for _, choice := range chunk.Choices {
						text += choice.Delta.Content
						if choice.FinishReason != "" {
							finish = choice.FinishReason
						}
					}
				}
				if err := stream.Err(); err != nil {
					t.Fatal(err)
				}
				if id == "" || strings.TrimSpace(text) == "" || finish != "stop" {
					t.Fatal("expected complete SSE answer")
				}
				verifyLiveReceipt(t, ctx, owner, id, mode.algo, model.Provider != "near")
			})
		}
	}
}
func TestLiveOpenAIResponses(t *testing.T) {
	models := liveModels(t, "responses")
	if len(models) != 2 {
		t.Fatal("expected NEAR and external Responses models")
	}
	for _, model := range models {
		for _, mode := range []liveMode{{nearai.Ed25519, false, false}, {nearai.ECDSA, false, false}, {nearai.Ed25519, false, true}} {
			t.Run(fmt.Sprintf("%s/%s/ohttp=%t", model.ID, mode.algo, mode.ohttp), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
				defer cancel()
				owner, client := liveOpenAI(t, mode)
				request := responses.ResponseNewParams{Model: model.ID, Input: responses.ResponseNewParamsInputUnion{OfString: openai.String("Reply with the word OK.")}, Store: openai.Bool(false), MaxOutputTokens: openai.Int(1024)}
				response, err := client.Responses.New(ctx, request)
				if err != nil {
					t.Fatal(err)
				}
				if response.ID == "" || response.Status != "completed" || len(response.Output) == 0 {
					t.Fatal("expected complete JSON response")
				}
				verifyLiveReceipt(t, ctx, owner, response.ID, mode.algo, true)
				stream := client.Responses.NewStreaming(ctx, request)
				defer stream.Close()
				id, completed := "", false
				for stream.Next() {
					event := stream.Current()
					if event.Type == "response.created" {
						id = event.Response.ID
					}
					if event.Type == "response.completed" {
						if event.Response.ID != id || event.Response.Status != "completed" || len(event.Response.Output) == 0 {
							t.Fatal("invalid completed response")
						}
						completed = true
					}
				}
				if err := stream.Err(); err != nil {
					t.Fatal(err)
				}
				if id == "" || !completed {
					t.Fatal("SSE must reach response.completed and EOF")
				}
				verifyLiveReceipt(t, ctx, owner, id, mode.algo, true)
			})
		}
	}
}
