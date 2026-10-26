// Package demo shares configuration and response handling for the runnable examples.
package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	nearai "github.com/nearai/inference-sdk/go"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

type Config struct {
	Key, BaseURL, Model string
	Algo                nearai.SigningAlgo
	OHTTP               bool
}

func Configuration(direct bool) (Config, error) {
	return ConfigurationForModel(direct, "z-ai/glm-5.3-flash")
}

func ConfigurationForModel(direct bool, defaultModel string) (Config, error) {
	c := Config{
		Key:     os.Getenv("NEARAI_API_KEY"),
		BaseURL: os.Getenv("NEARAI_BASE_URL"),
		Model:   os.Getenv("NEARAI_MODEL"),
		Algo:    nearai.SigningAlgo(os.Getenv("NEARAI_SIGNING_ALGO")),
		OHTTP:   os.Getenv("NEARAI_OHTTP") == "true",
	}
	if c.Key == "" {
		c.Key = os.Getenv("NEAR_AI_API_KEY")
	}
	if c.Key == "" {
		return c, fmt.Errorf("set NEARAI_API_KEY (or NEAR_AI_API_KEY)")
	}
	if c.BaseURL == "" {
		c.BaseURL = nearai.DefaultBaseURL
		if direct {
			c.BaseURL = "https://glm-5-3-flash.completions.near.ai/v1"
		}
	}
	if c.Model == "" {
		c.Model = defaultModel
	}
	if c.Algo == "" {
		c.Algo = nearai.Ed25519
	}
	if c.Algo != nearai.Ed25519 && c.Algo != nearai.ECDSA {
		return c, fmt.Errorf("NEARAI_SIGNING_ALGO must be ed25519 or ecdsa")
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/") + "/"
	return c, nil
}

// GatewayImages checks the same four Gateway build policies as the JS/Python examples.
// It does not approve model images/weights. Add commit pins for stricter policies.
func GatewayImages(ctx context.Context, deployment nearai.MeasuredDeployment) error {
	policies := map[string]nearai.ImageProvenancePolicy{}
	for name, workflow := range map[string]string{
		"cloud-api":         "build.yml",
		"cvm-ingress":       "build-push.yml",
		"dstack-vpc":        "build.yml",
		"dstack-vpc-client": "build.yml",
	} {
		policies["nearaidev/"+name] = nearai.ImageProvenancePolicy{Repository: "nearai/" + name, Workflow: ".github/workflows/" + workflow}
	}
	return nearai.VerifyDeploymentImageProvenance(ctx, deployment.AppCompose, policies, nearai.ProvenanceOptions{GitHubToken: os.Getenv("GITHUB_TOKEN")})
}
func body(model string, stream bool) []byte {
	b, _ := json.Marshal(map[string]any{
		"model":                 model,
		"messages":              []map[string]string{{"role": "user", "content": "Reply with the word ok."}},
		"max_completion_tokens": 1024,
		"stream":                stream,
	})
	return b
}
func request(ctx context.Context, c Config, stream bool) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"chat/completions", bytes.NewReader(body(c.Model, stream)))
	if err == nil {
		r.Header.Set("Authorization", "Bearer "+c.Key)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept-Encoding", "identity")
		r.Header.Set(nearai.NoAliasingHeader, "true")
	}
	return r, err
}

// EventDecoder retains partial records and UTF-8 across network chunks.
type EventDecoder struct {
	pending []byte
	started bool
	Done    bool
}

func (d *EventDecoder) Push(chunk []byte, eof bool) ([]map[string]any, error) {
	d.pending = append(d.pending, chunk...)
	if !d.started {
		if len(d.pending) < 3 && !eof {
			return nil, nil
		}
		d.pending = bytes.TrimPrefix(d.pending, []byte("\ufeff"))
		d.started = true
	}
	var events []map[string]any
	start, line := 0, 0
	for index := 0; index < len(d.pending); {
		ch := d.pending[index]
		if ch != '\r' && ch != '\n' {
			index++
			continue
		}
		if ch == '\r' && index+1 == len(d.pending) && !eof {
			break
		}
		end := index + 1
		if ch == '\r' && end < len(d.pending) && d.pending[end] == '\n' {
			end++
		}
		if index == line {
			record := strings.ReplaceAll(strings.ReplaceAll(string(d.pending[start:end]), "\r\n", "\n"), "\r", "\n")
			var values []string
			for _, line := range strings.Split(record, "\n") {
				if line == "data" {
					values = append(values, "")
				} else if strings.HasPrefix(line, "data:") {
					values = append(values, strings.TrimPrefix(line[5:], " "))
				}
			}
			data := strings.Join(values, "\n")
			if data == "[DONE]" {
				d.Done = true
			} else if data != "" {
				var event map[string]any
				if err := json.Unmarshal([]byte(data), &event); err != nil {
					return nil, err
				}
				if event["error"] != nil || event["type"] == "error" {
					return nil, fmt.Errorf("stream returned an error")
				}
				events = append(events, event)
			}
			start = end
		}
		line, index = end, end
	}
	d.pending = d.pending[start:]
	return events, nil
}
func Events(raw []byte) ([]map[string]any, error) { return new(EventDecoder).Push(raw, true) }
func textDelta(event map[string]any) string {
	switch event["type"] {
	case "content_block_delta":
		delta, _ := event["delta"].(map[string]any)
		text, _ := delta["text"].(string)
		return text
	case "response.output_text.delta":
		text, _ := event["delta"].(string)
		return text
	default:
		choices, _ := event["choices"].([]any)
		if len(choices) > 0 {
			choice, _ := choices[0].(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			text, _ := delta["content"].(string)
			return text
		}
	}
	return ""
}

type streamOutput struct{ decoder EventDecoder }

func (s *streamOutput) Write(chunk []byte) (int, error) {
	events, err := s.decoder.Push(chunk, false)
	if err != nil {
		return 0, err
	}
	for _, event := range events {
		fmt.Print(textDelta(event))
	}
	return len(chunk), nil
}
func ReadBody(r io.Reader, stream bool) ([]byte, error) {
	if !stream {
		return io.ReadAll(r)
	}
	output := new(streamOutput)
	raw, err := io.ReadAll(io.TeeReader(r, output))
	if err != nil {
		return nil, err
	}
	events, err := output.decoder.Push(nil, true)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		fmt.Print(textDelta(event))
	}
	fmt.Println()
	return raw, nil
}
func CompletionID(raw []byte, stream bool) (string, error) {
	var values []map[string]any
	if stream {
		var err error
		decoder := new(EventDecoder)
		values, err = decoder.Push(raw, true)
		if err == nil && !decoder.Done {
			err = fmt.Errorf("stream ended without [DONE]")
		}
		if err != nil {
			return "", err
		}
	} else {
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", err
		}
		values = append(values, value)
	}
	id := ""
	for _, value := range values {
		if next, ok := value["id"].(string); ok && next != "" {
			if id != "" && id != next {
				return "", fmt.Errorf("conflicting completion IDs")
			}
			id = next
		}
	}
	if id == "" {
		return "", fmt.Errorf("missing completion ID")
	}
	return id, nil
}

func DisplayChat(raw []byte, stream bool) error {
	if stream {
		return nil
	}
	var event map[string]any
	if err := json.Unmarshal(raw, &event); err != nil {
		return err
	}
	events := []map[string]any{event}
	text := ""
	for _, event := range events {
		choices, _ := event["choices"].([]any)
		if len(choices) == 0 {
			continue
		}
		choice, _ := choices[0].(map[string]any)
		key := "message"
		if stream {
			key = "delta"
		}
		message, _ := choice[key].(map[string]any)
		content, _ := message["content"].(string)
		text += content
	}
	fmt.Println(text)
	return nil
}

// RunIntegrated uses the verified transport for both JSON and SSE. Gateway mode
// applies image provenance policy; direct mode remains experimental without TLS binding.
func RunIntegrated(ctx context.Context, c Config, direct bool) error {
	opts := nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{APIKey: c.Key, BaseURL: c.BaseURL},
		SigningAlgo:   c.Algo,
		OHTTP:         c.OHTTP,
		E2EE:          true,
	}
	if !direct {
		opts.GatewayVerification.DeploymentVerifier = GatewayImages
		opts.ModelVerification.DeploymentVerifier = ModelImages
	}
	var client *nearai.InferenceClient
	var err error
	if direct {
		client, err = nearai.NewDirectInferenceClient(nearai.DirectInferenceOptions{InferenceOptions: opts})
	} else {
		client, err = nearai.NewInferenceClient(opts)
	}
	if err != nil {
		return err
	}
	defer client.Close()
	if _, err = client.Verify(ctx, c.Model); err != nil {
		return err
	}
	for _, stream := range []bool{false, true} {
		r, err := request(ctx, c, stream)
		if err != nil {
			return err
		}
		res, err := client.HTTPClient().Do(r)
		if err != nil {
			return err
		}
		raw, err := ReadBody(res.Body, stream)
		res.Body.Close()
		if err != nil {
			return err
		}
		if res.StatusCode != 200 {
			return fmt.Errorf("Chat HTTP %d", res.StatusCode)
		}
		id, err := CompletionID(raw, stream)
		if err != nil {
			return err
		}
		receipt, err := client.VerifyResponse(ctx, id)
		if err != nil {
			return err
		}
		fmt.Printf("Verified %s receipt, stream=%t\n", receipt.SignatureKind, stream)
		if err = DisplayChat(raw, stream); err != nil {
			return err
		}
	}
	return nil
}

// RunBare authenticates reports before selecting an E2EE key, pins Gateway TLS,
// captures exact ciphertext below decryption, and verifies receipts after EOF.
func RunBare(ctx context.Context, c Config, direct bool) error {
	opts := nearai.ClientOptions{APIKey: c.Key, BaseURL: c.BaseURL}
	var api *nearai.AttestationClient
	var gateway nearai.VerifiedAttestation
	var err error
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	if direct {
		api, err = nearai.NewDirectAttestationClient(opts)
	} else {
		api, err = nearai.NewAttestationClient(opts)
	}
	if err != nil {
		return err
	}
	if !direct {
		fetched, err := api.FetchGatewayAttestation(ctx, nearai.FetchOptions{SigningAlgo: c.Algo})
		if err != nil {
			return err
		}
		gateway, err = nearai.VerifyGatewayAttestation(ctx, fetched.Attestation, fetched.ClientBinding, nearai.VerificationOptions{DeploymentVerifier: GatewayImages})
		if err != nil {
			return err
		}
		if gateway.SPKIFingerprint == "" {
			return fmt.Errorf("Gateway did not supply attested TLS binding")
		}
		pinned, err := nearai.NewPinnedTransport(transport, gateway.SPKIFingerprint)
		if err != nil {
			return err
		}
		defer pinned.CloseIdleConnections()
		transport = pinned
		opts.HTTPClient = &http.Client{Transport: pinned}
		api, err = nearai.NewAttestationClient(opts)
		if err != nil {
			return err
		}
	}
	fetched, err := api.FetchModelAttestations(ctx, c.Model, nearai.FetchOptions{SigningAlgo: c.Algo})
	if err != nil {
		return err
	}
	var models []nearai.VerifiedAttestation
	if direct {
		verified, err := nearai.VerifyDirectModelAttestations(ctx, fetched, nearai.VerificationOptions{})
		if err != nil {
			return err
		}
		models = verified.Attestations
	} else {
		for _, report := range fetched.Attestations {
			verified, err := nearai.VerifyModelAttestation(ctx, report, fetched.ClientBinding, nearai.VerificationOptions{DeploymentVerifier: ModelImages})
			if err != nil {
				return err
			}
			models = append(models, verified)
		}
	}
	var recipient *nearai.VerifiedAttestation
	for i := range models {
		if models[i].Signer.SigningAlgo == c.Algo && models[i].SigningPublicKey != "" {
			recipient = &models[i]
			break
		}
	}
	if !direct && recipient == nil {
		return fmt.Errorf("no verified model public key")
	}
	httpClient := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, stream := range []bool{false, true} {
		r, err := request(ctx, c, stream)
		if err != nil {
			return err
		}
		var prepared *nearai.PreparedE2EEChatRequest
		if !direct {
			prepared, err = nearai.PrepareE2EEChatRequest(r, nearai.E2EEModelKey{SigningAlgo: c.Algo, PublicKey: recipient.SigningPublicKey})
			if err != nil {
				return err
			}
			r = prepared.Request
		}
		wireRequest, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return err
		}
		r.Body = io.NopCloser(bytes.NewReader(wireRequest))
		res, err := httpClient.Do(r)
		if err != nil {
			return err
		}
		if res.StatusCode != 200 {
			res.Body.Close()
			return fmt.Errorf("Chat HTTP %d", res.StatusCode)
		}
		var wire bytes.Buffer
		var plain []byte
		if direct {
			plain, err = ReadBody(io.TeeReader(res.Body, &wire), stream)
		} else if stream {
			decrypted := prepared.DecryptSSE(io.NopCloser(io.TeeReader(res.Body, &wire)))
			plain, err = ReadBody(decrypted, true)
			decrypted.Close()
		} else {
			var raw []byte
			raw, err = io.ReadAll(res.Body)
			wire.Write(raw)
			if err == nil {
				plain, err = prepared.DecryptJSON(raw)
			}
		}
		res.Body.Close()
		if err != nil {
			return err
		}
		id, err := CompletionID(plain, stream)
		if err != nil {
			return err
		}
		sig, err := api.FetchCompletionSignature(ctx, id, c.Algo)
		if err != nil {
			return err
		}
		if direct {
			_, err = nearai.VerifyDirectModelResponse(id, wireRequest, wire.Bytes(), sig, models)
		} else if sig.Kind == "gateway" {
			err = nearai.VerifyGatewayResponse(wireRequest, wire.Bytes(), sig, gateway)
		} else {
			var signer nearai.VerifiedAttestation
			signer, err = nearai.FindModelAttestationForSignature(models, sig)
			if err == nil {
				err = nearai.VerifyModelResponse(wireRequest, wire.Bytes(), sig, signer)
			}
		}
		if err != nil {
			return err
		}
		fmt.Printf("Verified %s ciphertext receipt, stream=%t\n", sig.Kind, stream)
		if err = DisplayChat(plain, stream); err != nil {
			return err
		}
	}
	return nil
}

// RunOpenAI covers the official OpenAI SDK through the verified Gateway transport.
func RunOpenAI(ctx context.Context, c Config) error {
	return runOpenAI(ctx, c, false)
}

// RunDirectOpenAI is experimental and does not authenticate direct TLS with attestation.
func RunDirectOpenAI(ctx context.Context, c Config) error {
	return runOpenAI(ctx, c, true)
}

func runOpenAI(ctx context.Context, c Config, direct bool) error {
	opts := nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{APIKey: c.Key, BaseURL: c.BaseURL},
		SigningAlgo:   c.Algo,
		OHTTP:         c.OHTTP,
		E2EE:          true,
	}
	var client *nearai.InferenceClient
	var err error
	if direct {
		client, err = nearai.NewDirectInferenceClient(nearai.DirectInferenceOptions{
			InferenceOptions: opts,
		})
	} else {
		client, err = nearai.NewInferenceClient(opts)
	}
	if err != nil {
		return err
	}
	defer client.Close()
	ai := openai.NewClient(
		option.WithAPIKey(c.Key),
		option.WithBaseURL(client.BaseURL()),
		option.WithHTTPClient(client.HTTPClient()),
		option.WithMaxRetries(0),
	)
	params := openai.ChatCompletionNewParams{
		Model:               c.Model,
		Messages:            []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Reply with the word ok.")},
		MaxCompletionTokens: openai.Int(1024),
	}
	completion, err := ai.Chat.Completions.New(ctx, params)
	if err != nil {
		return err
	}
	if _, err = client.VerifyResponse(ctx, completion.ID); err != nil {
		return err
	}
	if len(completion.Choices) == 0 || strings.TrimSpace(completion.Choices[0].Message.Content) == "" || completion.Choices[0].FinishReason != "stop" {
		return fmt.Errorf("expected a nonempty complete JSON answer")
	}
	fmt.Println(completion.Choices[0].Message.Content)
	stream := ai.Chat.Completions.NewStreaming(ctx, params)
	defer stream.Close()
	id, text, finish := "", "", ""
	for stream.Next() {
		chunk := stream.Current()
		if chunk.ID != "" {
			id = chunk.ID
		}
		for _, choice := range chunk.Choices {
			text += choice.Delta.Content
			fmt.Print(choice.Delta.Content)
			if choice.FinishReason != "" {
				finish = choice.FinishReason
			}
		}
	}
	fmt.Println()
	if err = stream.Err(); err != nil {
		return err
	}
	if id == "" || strings.TrimSpace(text) == "" || finish != "stop" {
		return fmt.Errorf("expected a nonempty complete SSE answer")
	}
	if _, err = client.VerifyResponse(ctx, id); err != nil {
		return err
	}
	fmt.Println("Verified streaming response.")
	return nil
}

// ModelImages authenticates recorded deployment intent, not running containers.
func ModelImages(ctx context.Context, deployment nearai.MeasuredDeployment) error {
	return nearai.VerifyComposeManagerDeploymentImageProvenance(ctx, deployment,
		map[string]nearai.ImageProvenancePolicy{"nearaidev/vllm-proxy-rs": {Repository: "nearai/inference-proxy", Workflow: ".github/workflows/build.yml"}},
		nearai.ComposeManagerDeploymentImageProvenanceOptions{
			ProvenanceOptions:         nearai.ProvenanceOptions{GitHubToken: os.Getenv("GITHUB_TOKEN")},
			ComposeManagerImagePolicy: nearai.ComposeManagerImagePolicy{ImageRepository: "nearaidev/compose-manager", Build: nearai.ImageProvenancePolicy{Repository: "nearai/compose-manager", Workflow: ".github/workflows/build.yml"}},
		})
}

// RunEndpoint covers native Messages/Responses JSON and SSE with the same receipt flow.
func RunEndpoint(ctx context.Context, c Config, messages bool) error {
	client, err := nearai.NewInferenceClient(nearai.InferenceOptions{ClientOptions: nearai.ClientOptions{APIKey: c.Key, BaseURL: c.BaseURL}, SigningAlgo: c.Algo, OHTTP: c.OHTTP})
	if err != nil {
		return err
	}
	defer client.Close()
	request := map[string]any{"model": c.Model}
	endpoint := "responses"
	if messages {
		endpoint = "messages"
		request["messages"] = []map[string]string{{"role": "user", "content": "Reply with the word ok."}}
		request["max_tokens"] = 128
	} else {
		request["input"], request["store"], request["max_output_tokens"] = "Reply with the word ok.", false, 1024
	}
	for _, stream := range []bool{false, true} {
		request["stream"] = stream
		var raw []byte
		if !stream {
			if messages {
				raw, err = client.CreateMessage(ctx, request)
			} else {
				raw, err = client.CreateResponse(ctx, request)
			}
		} else {
			body, e := json.Marshal(request)
			if e != nil {
				return e
			}
			req, e := http.NewRequestWithContext(ctx, "POST", client.BaseURL()+endpoint, bytes.NewReader(body))
			if e != nil {
				return e
			}
			res, e := client.HTTPClient().Do(req)
			if e != nil {
				return e
			}
			raw, err = ReadBody(res.Body, true)
			res.Body.Close()
			if res.StatusCode != http.StatusOK {
				return fmt.Errorf("%s HTTP status: %d", endpoint, res.StatusCode)
			}
		}
		if err != nil {
			return err
		}
		var id, text string
		if stream {
			events, e := Events(raw)
			if e != nil {
				return e
			}
			for _, event := range events {
				if messages {
					if event["type"] == "message_start" {
						message, _ := event["message"].(map[string]any)
						id, _ = message["id"].(string)
					}
					if event["type"] == "content_block_delta" {
						delta, _ := event["delta"].(map[string]any)
						part, _ := delta["text"].(string)
						text += part
					}
				} else {
					if event["type"] == "response.created" {
						response, _ := event["response"].(map[string]any)
						id, _ = response["id"].(string)
					}
					if event["type"] == "response.output_text.delta" {
						part, _ := event["delta"].(string)
						text += part
					}
				}
			}
		} else {
			var response struct {
				ID      string
				Content []struct{ Text string }
				Output  []struct{ Content []struct{ Text string } }
			}
			if err = json.Unmarshal(raw, &response); err != nil {
				return err
			}
			id = response.ID
			for _, block := range response.Content {
				text += block.Text
			}
			for _, item := range response.Output {
				for _, block := range item.Content {
					text += block.Text
				}
			}
		}
		if id == "" {
			return fmt.Errorf("missing response ID")
		}
		receipt, err := client.VerifyResponse(ctx, id)
		if err != nil {
			return err
		}
		fmt.Printf("Verified %s response, stream=%t.\n", receipt.SignatureKind, stream)
		if !stream {
			fmt.Println(text)
		}
	}
	return nil
}
