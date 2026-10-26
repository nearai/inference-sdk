// Anthropic Messages JSON/SSE with explicit Gateway receipt verification.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
)

func run() error {
	key := os.Getenv("NEARAI_API_KEY")
	if key == "" {
		return fmt.Errorf("set NEARAI_API_KEY")
	}
	client, err := nearai.NewInferenceClient(nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{APIKey: key},
	})
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	request := map[string]any{
		"model": "anthropic/claude-haiku-4-5", "max_tokens": 128,
		"messages": []map[string]string{{"role": "user", "content": "Reply with the word ok."}},
	}
	raw, err := client.CreateMessage(ctx, request)
	if err != nil {
		return err
	}
	var message struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(raw, &message); err != nil {
		return err
	}
	if _, err = client.VerifyResponse(ctx, message.ID); err != nil {
		return err
	}
	fmt.Println(string(raw))

	request["stream"] = true
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", client.BaseURL()+"messages", bytes.NewReader(body))
	if err != nil {
		return err
	}
	response, err := client.HTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Messages HTTP status: %s", response.Status)
	}
	// Applications may parse events incrementally. This example buffers to EOF
	// before reading message_start.message.id and verifying the complete stream.
	raw, err = io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	id := ""
	text := strings.TrimPrefix(string(raw), "\ufeff")
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	for _, record := range strings.Split(text, "\n\n") {
		var data []string
		for _, line := range strings.Split(record, "\n") {
			if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimPrefix(line[5:], " "))
			}
		}
		var event struct {
			Type    string `json:"type"`
			Message struct {
				ID string `json:"id"`
			} `json:"message"`
		}
		if json.Unmarshal([]byte(strings.Join(data, "\n")), &event) == nil && event.Type == "message_start" {
			id = event.Message.ID
		}
	}
	if id == "" {
		return fmt.Errorf("stream returned no message ID")
	}
	if _, err = client.VerifyResponse(ctx, id); err != nil {
		return err
	}
	fmt.Println(string(raw))
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
