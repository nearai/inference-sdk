package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"example.com/nearai-inference-example/internal/demo"
	nearai "github.com/nearai/inference-sdk/go"
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

	request := map[string]any{
		"model":             c.Model,
		"input":             "Reply with the word ok.",
		"max_output_tokens": 1024,
		"store":             false,
	}
	raw, err := client.CreateResponse(ctx, request)
	if err != nil {
		return err
	}
	var result struct {
		ID     string
		Output []struct{ Content []struct{ Text string } }
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		return err
	}
	receipt, err := client.VerifyResponse(ctx, result.ID)
	if err != nil {
		return err
	}
	fmt.Printf("Verified %s JSON response.\n", receipt.SignatureKind)
	for _, item := range result.Output {
		for _, block := range item.Content {
			fmt.Println(block.Text)
		}
	}

	request["stream"] = true
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BaseURL()+"responses", bytes.NewReader(body))
	if err != nil {
		return err
	}
	response, err := client.HTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("responses HTTP status: %d", response.StatusCode)
	}
	// ReadBody displays text as it arrives and retains events for the receipt ID.
	raw, err = demo.ReadBody(response.Body, true)
	if err != nil {
		return err
	}
	events, err := demo.Events(raw)
	if err != nil {
		return err
	}
	id := ""
	for _, event := range events {
		if event["type"] == "response.created" {
			value, _ := event["response"].(map[string]any)
			id, _ = value["id"].(string)
		}
	}
	if id == "" {
		return fmt.Errorf("stream returned no response ID")
	}
	receipt, err = client.VerifyResponse(ctx, id)
	if err != nil {
		return err
	}
	fmt.Printf("Verified %s streaming response.\n", receipt.SignatureKind)
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
