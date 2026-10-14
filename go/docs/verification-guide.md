# Go verification guide

Use the Go SDK to verify deployments before sending a prompt and explicitly
verify response signatures after receiving a completion. This guide covers
Gateway clients, the official OpenAI Go client, streaming, policies, encryption,
and experimental direct endpoints. See the [API reference](./api-reference.md)
for signatures, options, and result fields.

## Install

Requires Go 1.25.8 or later. In your Go module:

```sh
go get github.com/nearai/inference-sdk/go@v0.1.0
```

Set `NEARAI_API_KEY` for the examples below. The SDK itself takes credentials
explicitly. Choose a model available to your account; E2EE requires a model with
supported attestation and encryption keys.

## Send and verify a completion

The client verifies Gateway and supported model deployments before sending Chat.
`VerifyResponse` then verifies the exact request and response bytes against the
evidence captured before transmission. This example enables E2EE and prints the
response only after its receipt verifies.

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	apiKey := os.Getenv("NEARAI_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("set NEARAI_API_KEY")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := nearai.NewInferenceClient(nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{APIKey: apiKey},
		E2EE:          true,
	})
	if err != nil {
		return err
	}
	defer client.Close()

	body, err := client.CreateChatCompletion(ctx, map[string]any{
		"model":    "z-ai/glm-5.3-flash",
		"messages": []map[string]string{{"role": "user", "content": "Hello!"}},
	})
	if err != nil {
		return err
	}
	var completion struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &completion); err != nil {
		return err
	}
	if completion.ID == "" {
		return fmt.Errorf("completion has no ID")
	}

	verified, err := client.VerifyResponse(ctx, completion.ID)
	if err != nil {
		return err
	}
	fmt.Println(verified.SignatureKind)
	fmt.Println(string(body))
	return nil
}
```

Gateway E2EE defaults to off; use `E2EE: true` to enable it. A successful deployment
check does not verify a future response. Always call `VerifyResponse` explicitly
when your application requires a verified receipt.

## Verify a deployment before Chat

With the `client` and `ctx` from the example above:

```go
evidence, err := client.Verify(ctx, "z-ai/glm-5.3-flash")
if err != nil {
	return err
}
fmt.Println("Verified at:", evidence.VerifiedAt)
for _, model := range evidence.Models {
	fmt.Println(model.ModelName, model.TCBStatus)
}
```

`Verify` shares Chat's cache and in-flight work without sending an inference
request. Cached evidence keeps its original verification timestamp. Every
returned model report must pass; unsupported model providers use Gateway-only
verification, which cannot satisfy E2EE or a model deployment policy.

## Use the official OpenAI Go client

Install the official client alongside the NEAR AI SDK:

```sh
go get github.com/openai/openai-go/v3
```

The following function accepts an existing NEAR AI client and uses its verified
transport. Add these imports to your application:

```go
import (
	"context"
	"fmt"
	"strings"

	nearai "github.com/nearai/inference-sdk/go"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)
```

```go
func complete(ctx context.Context, client *nearai.InferenceClient, apiKey, model string) error {
	ai := openai.NewClient(
		option.WithAPIKey(apiKey),
		option.WithBaseURL(client.BaseURL()),
		option.WithHTTPClient(client.HTTPClient()),
		option.WithMaxRetries(0),
	)

	response, err := ai.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Model: model,
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage("Hello!"),
		},
	})
	if err != nil {
		return err
	}

	if _, err := client.VerifyResponse(ctx, response.ID); err != nil {
		return err
	}
	for _, choice := range response.Choices {
		fmt.Println(choice.Message.Content)
	}
	return nil
}
```

Use the configured `BaseURL` and HTTP client together. Disable OpenAI automatic
retries to avoid replaying completion requests. This adapter supports Chat
Completions only; use `AttestationClient` for evidence and metadata.

## Streaming

Using the same imports, consume every chunk, check the stream error, close the
stream, and then verify its completion ID. This example buffers display text
until signature verification succeeds:

```go
func streamCompletion(ctx context.Context, client *nearai.InferenceClient, apiKey, model string) error {
	ai := openai.NewClient(
		option.WithAPIKey(apiKey),
		option.WithBaseURL(client.BaseURL()),
		option.WithHTTPClient(client.HTTPClient()),
		option.WithMaxRetries(0),
	)

	stream := ai.Chat.Completions.NewStreaming(ctx, openai.ChatCompletionNewParams{
		Model: model,
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage("Hello!"),
		},
	})
	defer stream.Close()

	var completionID string
	var output strings.Builder
	for stream.Next() {
		chunk := stream.Current()
		if chunk.ID != "" {
			completionID = chunk.ID
		}
		for _, choice := range chunk.Choices {
			output.WriteString(choice.Delta.Content)
		}
	}
	if err := stream.Err(); err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	if completionID == "" {
		return fmt.Errorf("stream has no completion ID")
	}

	if _, err := client.VerifyResponse(ctx, completionID); err != nil {
		return err
	}
	fmt.Println(output.String())
	return nil
}
```

You can display chunks immediately, but that output is not signature-verified
until `VerifyResponse` succeeds. Close abandoned streams to cancel their requests.
Incomplete or failed bodies cannot be verified later. With raw `net/http`, consume
the response body through EOF and close it; SSE events may span multiple reads.

## Configure verification and deployment policies

The default policy accepts `UpToDate` and `OutOfDate` TCB statuses, rejects debug
quotes, and verifies GPU evidence when present. Require stricter status and GPU
policies through `ModelVerification` (or `GatewayVerification` where appropriate):

```go
options := nearai.InferenceOptions{
	ClientOptions: nearai.ClientOptions{APIKey: apiKey},
	ModelVerification: nearai.VerificationOptions{
		Policy: nearai.AttestationPolicy{
			AcceptedTCBStatuses: []string{"UpToDate"},
			RequireGPUEvidence:  true,
		},
	},
}
```

Pass `options` to `NewInferenceClient`. An explicitly empty status list rejects
all statuses; nil selects the defaults. A valid quote does not automatically
approve a particular application image or source revision.

Use `DeploymentPolicy` for model-aware admission. For example, this function
checks every configured image repository against your application-owned build
policies before prompts are sent:

```go
func imagePolicy(
	policies map[string]nearai.ImageProvenancePolicy,
	provenance nearai.ProvenanceOptions,
) func(context.Context, string, nearai.MeasuredDeployment) error {
	return func(ctx context.Context, model string, deployment nearai.MeasuredDeployment) error {
		if err := nearai.VerifyDeploymentImageProvenance(
			ctx, deployment.AppCompose, policies, provenance,
		); err != nil {
			return fmt.Errorf("reject deployment for %s: %w", model, err)
		}
		return nil
	}
}
```

Assign the returned callback to `options.DeploymentPolicy`. Supply nonempty
policies keyed by image repository, specifying the trusted GitHub repository,
workflow, and source constraints. Use `Commit` to pin reviewed source. See the
[image provenance API](./api-reference.md#image-provenance-api) and the
[runnable examples](../../examples/example-go/README.md) for policy configuration.
Gateway image policies belong in `GatewayVerification.DeploymentVerifier`.

Custom quote, GPU, and deployment verifiers are trusted application code. They
must authenticate evidence, rather than merely parse it.

## Encryption and TLS binding

Enable `E2EE: true` to encrypt supported content fields to an attested model key.
Model IDs, roles, tool-call IDs, and other protocol metadata remain visible.
Enable `OHTTP: true` independently to encrypt the inner Chat HTTP exchange to
the Gateway; it requires Ed25519 and can be combined with E2EE. Authorization
remains visible to the receiving endpoint. See the
[encryption reference](./api-reference.md#encryption) for exact field coverage.

Gateway clients bind TLS to the attested Gateway identity before sending prompts
and subsequent evidence/signature requests. Keep normal TLS validation enabled.
`DisableTLSBinding: true` opts out of this attested identity check for an
application proxy; consider that changed trust boundary before using it.

## Experimental direct endpoints

Direct clients require an explicit model endpoint URL and default E2EE to on:

```go
client, err := nearai.NewDirectInferenceClient(nearai.DirectInferenceOptions{
	InferenceOptions: nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{
			APIKey:  apiKey,
			BaseURL: directBaseURL,
		},
	},
})
if err != nil {
	return err
}
defer client.Close()
```

The Chat, OpenAI adapter, streaming, and `VerifyResponse` APIs are the same.
Set `DisableE2EE: true` only when deliberately opting out. Direct clients omit
Gateway verification and do not bind TLS identity to attestation; normal HTTPS
validation still applies. They are experimental and not recommended for
production. Use Gateway clients for production integrations.

Direct response results include all matching deployments in `Attestations` and
leave `Attestation` nil: a shared signing key cannot identify one serving instance.

## Manual verification

For applications that own HTTP requests, use the standalone APIs in this order:

1. Create an `AttestationClient` and fetch Gateway evidence with a fresh binding.
2. Authenticate the report with `VerifyGatewayAttestation`.
3. Build a pinned transport with `NewPinnedTransport` using the verified Gateway
   fingerprint, then use it for model evidence, Chat, and receipt retrieval.
4. Fetch model evidence and verify every returned report with
   `VerifyModelAttestation`, applying your deployment policy.
5. If encrypting manually, pass a verified model key to `PrepareE2EEChatRequest`.
   Retain the exact encrypted request and response bytes before decrypting.
6. Fetch the completion signature and verify its kind with `VerifyModelResponse`
   or `VerifyGatewayResponse` against the corresponding authenticated evidence.

Fetching evidence and decrypting output alone do not verify a receipt. Do not
reserialize JSON for signature checking. For direct endpoints, use the direct
attestation client and plural direct verification helpers. The
[bare examples](../../examples/example-go/README.md) implement the full flows,
including streaming and exact ciphertext retention.

A `provider_tee` receipt authenticates the model signer's exact bytes and canonical
model ID. A `gateway` receipt authenticates the Gateway's exact client-visible
bytes. Neither by itself proves a complete chain through intermediary rewrites.

## Retention and lifecycle

Reuse a client across requests and close it when your application shuts down.
Close every response body. `Close` cancels shared work and active requests;
caller-supplied HTTP clients and transports remain caller-owned.

Attestation reuse and response retention default to one hour. Set `AttestationTTL`
or `ResponseTTL` to a duration pointer to customize them. Pointer-to-zero disables
the corresponding cache; disabling response retention prevents later receipt
verification. Expired or evicted receipts cannot be verified. Check the
[cache limits](./api-reference.md#clients-and-lifecycle) when sizing services that
retain large or streaming completions.

## Handle errors

Use Go's `errors.As` and `errors.Is`; add `"errors"` to your imports:

```go
func inspectError(err error) {
	var sdkError *nearai.Error
	if errors.As(err, &sdkError) {
		fmt.Println(sdkError.Code, sdkError.Retryable, sdkError.Details)
	}
	if errors.Is(err, context.Canceled) {
		fmt.Println("request canceled")
	}
}
```

Retryable signature retrieval failures can be retried by calling `VerifyResponse`
again while its receipt remains retained. Use bounded retries and a context
deadline. Do not replay Chat just because a receipt fetch failed. Verification
failures remain failures; the SDK never silently falls back to unverified Chat.
