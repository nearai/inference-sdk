package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"example.com/nearai-inference-example/internal/demo"
	nearai "github.com/nearai/inference-sdk/go"
)

func run() error {
	c, err := demo.ConfigurationForModel(false, "")
	if err != nil {
		return err
	}
	if c.Model == "" {
		return fmt.Errorf("NEARAI_MODEL is required")
	}
	expected := os.Getenv("NEARAI_EXPECT_SIGNATURE_KIND")
	if expected == "" {
		expected = "gateway"
	}
	if expected != "gateway" && expected != "provider_tee" {
		return fmt.Errorf("NEARAI_EXPECT_SIGNATURE_KIND must be gateway or provider_tee")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := nearai.NewInferenceClient(nearai.InferenceOptions{ClientOptions: nearai.ClientOptions{APIKey: c.Key, BaseURL: c.BaseURL}, SigningAlgo: c.Algo})
	if err != nil {
		return err
	}
	defer client.Close()
	if expected == "provider_tee" {
		verified, err := client.Verify(ctx, c.Model)
		if err != nil {
			return err
		}
		if len(verified.Models) == 0 {
			return fmt.Errorf("model evidence is required")
		}
	}
	request := nearai.SystemOneRequest{Model: c.Model, State: map[string]string{"message": "I was charged twice for my subscription. Please help."}, Questions: map[string]nearai.SystemOneQuestion{
		"billing": {Type: "noul", Instructions: "Is this about billing?"},
		"team":    {Type: "choice", Instructions: "Which team should handle this?", Criteria: map[string]string{"billing": "Payments and subscriptions", "support": "Technical issues"}},
		"urgency": {Type: "score", Instructions: "How urgent is this request?", Criteria: []string{"Routine", "Needs prompt attention", "Critical"}},
	}}
	result, err := client.CreateSystemOne(ctx, request)
	if err != nil {
		return err
	}
	receipt, err := client.VerifyResponse(ctx, result.DecisionID)
	if err != nil {
		return err
	}
	if receipt.SignatureKind != expected {
		return fmt.Errorf("expected %s, got %s", expected, receipt.SignatureKind)
	}
	fmt.Printf("Verified %s receipt %s.\n", receipt.SignatureKind, result.DecisionID)
	output, err := json.MarshalIndent(map[string]any{"answers": result.Data.Answers, "usage": result.Data.Usage}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
