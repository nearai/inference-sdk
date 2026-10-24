//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
)

func TestResponsesJSONAndSSE(t *testing.T) {
	selected := selectedModels(t, "responses")
	if len(selected) != 2 {
		t.Fatal("expected NEAR and OpenAI Responses models")
	}
	for _, selectedModel := range selected {
		model := selectedModel.ID
		for _, ohttp := range []bool{false, true} {
			t.Run(fmt.Sprintf("model=%s/ohttp=%t", model, ohttp), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
				defer cancel()
				client, err := nearai.NewInferenceClient(nearai.InferenceOptions{
					ClientOptions: nearai.ClientOptions{APIKey: required(t, "NEARAI_API_KEY"), BaseURL: required(t, "NEARAI_BASE_URL")},
					OHTTP:         ohttp,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				for _, stream := range []bool{false, true} {
					request := map[string]any{
						"model": model, "input": "Reply with the word OK.",
						"store": false, "max_output_tokens": 1024, "stream": stream,
					}
					var result struct {
						ID, Status string
						Output     []json.RawMessage
					}
					if stream {
						body, err := json.Marshal(request)
						if err != nil {
							t.Fatal(err)
						}
						req, err := http.NewRequestWithContext(ctx, http.MethodPost,
							strings.TrimRight(client.BaseURL(), "/")+"/responses", bytes.NewReader(body))
						if err != nil {
							t.Fatal(err)
						}
						req.Header.Set("Content-Type", "application/json")
						res, err := client.HTTPClient().Do(req)
						if err != nil {
							t.Fatal(err)
						}
						raw := readResponse(t, res)
						createdID, completed := "", false
						for _, line := range strings.Split(string(raw), "\n") {
							data, ok := strings.CutPrefix(line, "data:")
							if !ok || strings.TrimSpace(data) == "[DONE]" {
								continue
							}
							var event struct {
								Type     string
								Response json.RawMessage
							}
							if err := json.Unmarshal([]byte(data), &event); err != nil {
								t.Fatal(err)
							}
							switch event.Type {
							case "response.created":
								if err := json.Unmarshal(event.Response, &result); err != nil {
									t.Fatal(err)
								}
								createdID = result.ID
							case "response.completed":
								if err := json.Unmarshal(event.Response, &result); err != nil {
									t.Fatal(err)
								}
								if result.ID != createdID {
									t.Fatal("conflicting response IDs")
								}
								completed = true
							}
						}
						if createdID == "" || !completed {
							t.Fatal("SSE must reach response.completed and EOF")
						}
					} else {
						raw, err := client.CreateResponse(ctx, request)
						if err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal(raw, &result); err != nil {
							t.Fatal(err)
						}
					}
					if result.ID == "" || result.Status != "completed" || len(result.Output) == 0 {
						t.Fatal("expected completed Responses output")
					}
					receiptCtx, receiptCancel := context.WithTimeout(ctx, 15*time.Second)
					err = retry(receiptCtx, func() error {
						receipt, err := client.VerifyResponse(receiptCtx, result.ID)
						if err == nil && (receipt.ID != result.ID || receipt.SignatureKind != "gateway") {
							t.Fatal("expected matching Gateway receipt")
						}
						return err
					})
					receiptCancel()
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("Responses stream=%t: verified Gateway receipt", stream)
				}
			})
		}
	}
}
