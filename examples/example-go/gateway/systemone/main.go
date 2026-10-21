package main

import (
	"context"
	"errors"
	"fmt"
	nearai "github.com/nearai/inference-sdk/go"
	"log"
	"os"
	"time"
)

func run() error {
	key, model := os.Getenv("NEARAI_API_KEY"), os.Getenv("NEARAI_SYSTEMONE_MODEL")
	if key == "" || model == "" {
		return errors.New("NEARAI_API_KEY and NEARAI_SYSTEMONE_MODEL are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client, err := nearai.NewInferenceClient(nearai.InferenceOptions{ClientOptions: nearai.ClientOptions{APIKey: key, BaseURL: os.Getenv("NEARAI_BASE_URL")}})
	if err != nil {
		return err
	}
	defer client.Close()
	result, err := client.CreateSystemOne(ctx, nearai.SystemOneRequest{Model: model, State: map[string]string{"message": "I was charged twice for my subscription."}, Questions: map[string]nearai.SystemOneQuestion{"billing": {Type: "noul", Instructions: "Is this about billing?"}}})
	if err != nil {
		return err
	}
	var receipt nearai.VerifiedCompletionResult
	for _, delay := range []time.Duration{0, 500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second} {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		receipt, err = client.VerifyResponse(ctx, result.DecisionID)
		var sdk *nearai.Error
		if err == nil || !errors.As(err, &sdk) || (!sdk.Retryable && sdk.Code != "api.completion_signature_unavailable") {
			break
		}
	}
	if err != nil {
		return err
	}
	fmt.Printf("Verified %s receipt: %+v\n", receipt.SignatureKind, result.Data.Answers)
	return nil
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
