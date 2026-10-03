package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

func main() {
	key := os.Getenv("NEARAI_API_KEY")
	if key == "" {
		key = os.Getenv("NEAR_AI_API_KEY")
	}
	if key == "" {
		log.Fatal("Set NEARAI_API_KEY (or NEAR_AI_API_KEY)")
	}
	model := os.Getenv("NEARAI_MODEL")
	if model == "" {
		model = "z-ai/glm-5.3-flash"
	}
	client, err := nearai.NewInferenceClient(nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{APIKey: key}, E2EE: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	ai := openai.NewClient(option.WithAPIKey(key), option.WithBaseURL(client.BaseURL()), option.WithHTTPClient(client.HTTPClient()), option.WithMaxRetries(0))
	completion, err := ai.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Model: model, Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Hello!")},
	})
	if err != nil {
		log.Fatal(err)
	}
	verified, err := client.VerifyResponse(ctx, completion.ID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Verified %s response\n", verified.SignatureKind)
	if len(completion.Choices) > 0 {
		fmt.Println(completion.Choices[0].Message.Content)
	}
}
