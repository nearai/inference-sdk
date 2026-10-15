// Package demo shares configuration and response handling for the runnable examples.
package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

type Config struct {
	Key, BaseURL, Model string
	Algo                nearai.SigningAlgo
}

func Configuration(direct bool) (Config, error) {
	c := Config{
		Key:     os.Getenv("NEARAI_API_KEY"),
		BaseURL: os.Getenv("NEARAI_BASE_URL"),
		Model:   os.Getenv("NEARAI_MODEL"),
		Algo:    nearai.SigningAlgo(os.Getenv("NEARAI_SIGNING_ALGO")),
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
		c.Model = "z-ai/glm-5.3-flash"
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
		"messages":              []map[string]string{{"role": "user", "content": "Reply with the word OK."}},
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
func readAll(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, (64<<20)+1))
	if err == nil && len(b) > 64<<20 {
		err = fmt.Errorf("response exceeds 64 MiB")
	}
	return b, err
}

// CompletionID parses complete JSON or SSE after HTTP EOF, including after [DONE].
func CompletionID(raw []byte, stream bool) (string, error) {
	if !stream {
		var v struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", err
		}
		if v.ID == "" {
			return "", fmt.Errorf("missing completion ID")
		}
		return v.ID, nil
	}
	id, done := "", false
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r", ""), "\n") {
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(line[5:])
		if data == "[DONE]" {
			done = true
			continue
		}
		if data == "" {
			continue
		}
		var v struct {
			ID    string `json:"id"`
			Error any    `json:"error"`
		}
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			return "", err
		}
		if v.Error != nil {
			return "", fmt.Errorf("stream returned an error")
		}
		if v.ID != "" {
			if id != "" && id != v.ID {
				return "", fmt.Errorf("conflicting completion IDs")
			}
			id = v.ID
		}
	}
	if !done || id == "" {
		return "", fmt.Errorf("incomplete SSE response")
	}
	return id, nil
}

// Retry receipt propagation only; never replay Chat or retry cryptographic failures.
func Retry(ctx context.Context, check func() error) error {
	for _, delay := range []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 0} {
		err := check()
		if err == nil {
			return nil
		}
		var sdk *nearai.Error
		if !errors.As(err, &sdk) || (!sdk.Retryable && sdk.Code != "api.completion_signature_unavailable") || delay == 0 {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

// RunIntegrated uses the verified transport for both JSON and SSE. Gateway mode
// applies image provenance policy; direct mode remains experimental without TLS binding.
func RunIntegrated(ctx context.Context, c Config, direct bool) error {
	opts := nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{APIKey: c.Key, BaseURL: c.BaseURL},
		SigningAlgo:   c.Algo,
		E2EE:          true,
	}
	if !direct {
		opts.GatewayVerification.DeploymentVerifier = GatewayImages
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
		raw, err := readAll(res.Body)
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
		var receipt nearai.VerifiedCompletionResult
		if err = Retry(ctx, func() error { var e error; receipt, e = client.VerifyResponse(ctx, id); return e }); err != nil {
			return err
		}
		fmt.Printf("Verified %s receipt, stream=%t\n%s\n", receipt.SignatureKind, stream, raw)
	}
	return nil
}

// RunBare authenticates reports before selecting an E2EE key, pins Gateway TLS,
// captures exact ciphertext below decryption, and verifies receipts before display.
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
			verified, err := nearai.VerifyModelAttestation(ctx, report, fetched.ClientBinding, nearai.VerificationOptions{})
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
	if recipient == nil {
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
		prepared, err := nearai.PrepareE2EEChatRequest(r, nearai.E2EEModelKey{SigningAlgo: c.Algo, PublicKey: recipient.SigningPublicKey})
		if err != nil {
			return err
		}
		wireRequest, err := readAll(prepared.Request.Body)
		prepared.Request.Body.Close()
		if err != nil {
			return err
		}
		prepared.Request.Body = io.NopCloser(bytes.NewReader(wireRequest))
		res, err := httpClient.Do(prepared.Request)
		if err != nil {
			return err
		}
		if res.StatusCode != 200 {
			res.Body.Close()
			return fmt.Errorf("Chat HTTP %d", res.StatusCode)
		}
		var wire bytes.Buffer
		var plain []byte
		if stream {
			decrypted := prepared.DecryptSSE(io.NopCloser(io.TeeReader(res.Body, &wire)))
			plain, err = readAll(decrypted)
			decrypted.Close()
		} else {
			var raw []byte
			raw, err = readAll(res.Body)
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
		var sig nearai.CompletionSignature
		if err = Retry(ctx, func() error { var e error; sig, e = api.FetchCompletionSignature(ctx, id, c.Algo); return e }); err != nil {
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
		fmt.Printf("Verified %s ciphertext receipt, stream=%t\n%s\n", sig.Kind, stream, plain)
	}
	return nil
}

// RunOpenAI covers the official OpenAI SDK through the verified Gateway transport.
func RunOpenAI(ctx context.Context, c Config) error {
	return runOpenAI(ctx, c, openAIRunOptions{})
}

// RunLiveOpenAI adds the live suite's bounded retry policy for rejected Chat requests.
func RunLiveOpenAI(ctx context.Context, c Config) error {
	return runOpenAI(ctx, c, openAIRunOptions{retryRateLimits: true})
}

// RunDirectOpenAI is experimental and does not authenticate direct TLS with attestation.
func RunDirectOpenAI(ctx context.Context, c Config) error {
	return runOpenAI(ctx, c, openAIRunOptions{direct: true})
}

type openAIRunOptions struct {
	direct, retryRateLimits bool
}

func runOpenAI(ctx context.Context, c Config, runOptions openAIRunOptions) error {
	opts := nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{APIKey: c.Key, BaseURL: c.BaseURL},
		SigningAlgo:   c.Algo,
		E2EE:          true,
	}
	var client *nearai.InferenceClient
	var err error
	if runOptions.direct {
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
	httpClient := client.HTTPClient()
	if runOptions.retryRateLimits {
		httpClient.Transport = &rateLimitTransport{base: httpClient.Transport, sleep: sleepRateLimit}
	}
	ai := openai.NewClient(
		option.WithAPIKey(c.Key),
		option.WithBaseURL(client.BaseURL()),
		option.WithHTTPClient(httpClient),
		option.WithMaxRetries(0),
	)
	params := openai.ChatCompletionNewParams{
		Model:               c.Model,
		Messages:            []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Reply with the word OK.")},
		MaxCompletionTokens: openai.Int(1024),
	}
	completion, err := ai.Chat.Completions.New(ctx, params)
	if err != nil {
		return err
	}
	if err = Retry(ctx, func() error { _, e := client.VerifyResponse(ctx, completion.ID); return e }); err != nil {
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
			if choice.FinishReason != "" {
				finish = choice.FinishReason
			}
		}
	}
	if err = stream.Err(); err != nil {
		return err
	}
	if id == "" || strings.TrimSpace(text) == "" || finish != "stop" {
		return fmt.Errorf("expected a nonempty complete SSE answer")
	}
	if err = Retry(ctx, func() error { _, e := client.VerifyResponse(ctx, id); return e }); err != nil {
		return err
	}
	fmt.Println(text)
	return nil
}
