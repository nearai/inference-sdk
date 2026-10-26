// Official Anthropic SDK with Gateway preflight and JSON/SSE receipt verification.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
	nearai "github.com/nearai/inference-sdk/go"
)

func run() error {
	key := os.Getenv("NEARAI_API_KEY")
	if key == "" {
		return fmt.Errorf("set NEARAI_API_KEY")
	}
	baseURL := os.Getenv("NEARAI_BASE_URL")
	if baseURL == "" {
		baseURL = "https://cloud-api.near.ai/v1/"
	}
	model := os.Getenv("NEARAI_MODEL")
	if model == "" {
		model = "anthropic/claude-haiku-4-5"
	}
	inference, err := nearai.NewInferenceClient(nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{APIKey: key, BaseURL: baseURL},
		OHTTP:         os.Getenv("NEARAI_OHTTP") == "true",
	})
	if err != nil {
		return err
	}
	defer inference.Close()
	client := anthropic.NewClient(
		option.WithAPIKey(key),
		// The official SDK appends /v1/messages to this API root.
		option.WithBaseURL(strings.TrimSuffix(inference.BaseURL(), "v1/")),
		option.WithHTTPClient(inference.HTTPClient()),
		option.WithMaxRetries(0),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	request := anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 128,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock("Reply with the word ok.")),
		},
	}
	message, err := client.Messages.New(ctx, request)
	if err != nil {
		return err
	}
	receipt, err := inference.VerifyResponse(ctx, message.ID)
	if err != nil {
		return err
	}
	fmt.Printf("Verified %s JSON response.\n", receipt.SignatureKind)
	for _, block := range message.Content {
		if block.Type == "text" {
			fmt.Println(block.Text)
		}
	}

	stream := client.Messages.NewStreaming(ctx, request)
	defer stream.Close()
	accumulated := anthropic.Message{}
	// Retain streamed content until the complete response has been verified.
	for stream.Next() {
		if err := accumulated.Accumulate(stream.Current()); err != nil {
			return err
		}
	}
	if err := stream.Err(); err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	receipt, err = inference.VerifyResponse(ctx, accumulated.ID)
	if err != nil {
		return err
	}
	fmt.Printf("Verified %s streaming response.\n", receipt.SignatureKind)
	for _, block := range accumulated.Content {
		if block.Type == "text" {
			fmt.Println(block.Text)
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
