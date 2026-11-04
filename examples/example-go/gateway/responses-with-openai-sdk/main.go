// Responses creation through the official OpenAI Go client and verified transport.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"example.com/nearai-inference-example/internal/demo"
	nearai "github.com/nearai/inference-sdk/go"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/responses"
)

func run() error {
	c, err := demo.ConfigurationForModel(false, "z-ai/glm-5.3-flash")
	if err != nil {
		return err
	}

	client, err := nearai.NewInferenceClient(nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{APIKey: c.Key, BaseURL: c.BaseURL},
		SigningAlgo:   c.Algo,
		OHTTP:         c.OHTTP,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	api := openai.NewClient(option.WithAPIKey(c.Key), option.WithBaseURL(client.BaseURL()), option.WithHTTPClient(client.HTTPClient()), option.WithMaxRetries(0))
	request := responses.ResponseNewParams{
		Model:           c.Model,
		Input:           responses.ResponseNewParamsInputUnion{OfString: openai.String("Reply with the word ok.")},
		Store:           openai.Bool(false),
		MaxOutputTokens: openai.Int(1024),
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
	fmt.Println()
	if err = stream.Err(); err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("stream returned no response ID")
	}
	// Verify the receipt after consuming the complete stream.
	if _, err = client.VerifyResponse(ctx, id); err != nil {
		return err
	}
	fmt.Println("Verified Gateway Responses receipt.")
	return nil
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
