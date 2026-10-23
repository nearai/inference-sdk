//go:build e2e

package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"example.com/nearai-inference-example/internal/demo"
)

func TestLiveOpenAI(t *testing.T) {
	for _, name := range []string{"NEARAI_API_KEY", "NEARAI_BASE_URL", "NEARAI_E2E_MODELS"} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is required", name)
		}
	}
	var models []struct{ ID, Provider, Endpoint string }
	if err := json.Unmarshal([]byte(os.Getenv("NEARAI_E2E_MODELS")), &models); err != nil {
		t.Fatal(err)
	}
	c, err := demo.Configuration(false)
	if err != nil {
		t.Fatal(err)
	}
	c.Model = ""
	for _, m := range models {
		if m.Endpoint == "chat" && m.Provider == "near" {
			c.Model = m.ID
			break
		}
	}
	if c.Model == "" {
		t.Fatal("expected a NEAR model")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	if err = demo.RunOpenAI(ctx, c); err != nil {
		t.Fatal(err)
	}
}
