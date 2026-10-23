// Responses creation through the official OpenAI Go client and verified transport.
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
	"github.com/openai/openai-go/v3/responses"
)

func run() error {
	apiKey := os.Getenv("NEARAI_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("set NEARAI_API_KEY")
	}
	client, err := nearai.NewInferenceClient(nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{APIKey: apiKey},
		// OHTTP may be enabled independently; field-level E2EE is unavailable for Responses.
	})
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	api := openai.NewClient(option.WithAPIKey(apiKey), option.WithBaseURL(client.BaseURL()), option.WithHTTPClient(client.HTTPClient()), option.WithMaxRetries(0))
	request := responses.ResponseNewParams{
		Model: "z-ai/glm-5.3-flash",
		Input: responses.ResponseNewParamsInputUnion{OfString: openai.String("Reply with the word ok.")},
		Store: openai.Bool(false),
	}
	response, err := api.Responses.New(ctx, request)
	if err != nil {
		return err
	}
	if _, err = client.VerifyResponse(ctx, response.ID); err != nil {
		return err
	}
	fmt.Println(response.OutputText())
	stream := api.Responses.NewStreaming(ctx, request)
	defer stream.Close()
	id := ""
	for stream.Next() {
		event := stream.Current()
		if event.Type == "response.created" {
			id = event.Response.ID
		}
		if event.Type == "response.output_text.delta" {
			fmt.Print(event.Delta)
		}
	}
	if err = stream.Err(); err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("stream returned no response ID")
	}
	// Streamed text is provisional until the exact complete response is verified.
	if _, err = client.VerifyResponse(ctx, id); err != nil {
		return err
	}
	fmt.Println("\nVerified Gateway Responses receipt.")
	return nil
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
