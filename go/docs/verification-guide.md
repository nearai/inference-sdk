# Go verification guide

Use the Go SDK to verify deployments before sending a prompt and explicitly
verify response signatures after receiving a completion. This guide covers
Gateway clients, the official OpenAI Go client, streaming, policies, encryption,
and experimental direct endpoints. See the [API reference](./api-reference.md)
for signatures, options, and result fields.

## Install

Requires Go 1.26.10 or later. In your Go module:

```sh
go get github.com/nearai/inference-sdk/go
```

Set `NEARAI_API_KEY` for the examples below. The SDK itself takes credentials
explicitly. Choose a model available to your account; E2EE requires a model with
supported attestation and encryption keys.

## Send and verify a completion

The Gateway client verifies Gateway evidence and every returned model report
before inference. This example enables E2EE and verifies the response before
printing it.

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

E2EE defaults to `false`; set `E2EE: true` to enable it.

## Verify a deployment before Chat

With the `client` and `ctx` from the example above:

```go
evidence, err := client.Verify(ctx, "z-ai/glm-5.3-flash")
if err != nil {
	return err
}
fmt.Println("Verified at:", evidence.VerifiedAt)
for _, modelAttestation := range evidence.Models {
	fmt.Println(modelAttestation.ModelName, modelAttestation.TCBStatus)
}
```

`Verify` returns the verified Gateway, all model reports, and the verification
time. Models without model attestation use Gateway-only verification.
E2EE and model deployment policies require model attestation.

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
retries to avoid replaying inference requests. This adapter supports Chat
Completions and Gateway [Responses creation](#responses-api); use
`AttestationClient` for evidence and metadata.

## Streaming

Add `"strings"` to the imports above for the streaming example. Consume every
chunk, check the stream error, close the stream, and then verify its completion ID. This example buffers display text
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

With raw `net/http`, consume the response body to EOF before verification.
Close the body when finished.

## Verify System One decisions

Create a Gateway client with E2EE and OHTTP disabled. Send structured questions
with `client.CreateSystemOne(ctx, request)`, then call
`client.VerifyResponse(ctx, result.DecisionID)` before using `result.Data.Answers`.

The [API reference](./api-reference.md#system-one-decisions) describes request
and result types. To try a complete application, run the
[decision example](../../examples/example-go/gateway/systemone/main.go).

## Messages API

Gateway clients support Messages creation as JSON or SSE, with optional OHTTP
(Ed25519). Use field-level E2EE disabled.

Verify the message `id` after reading a JSON response, or `message_start.message.id`
after consuming the stream. Messages use Gateway receipts.

```go
raw, err := client.CreateMessage(ctx, map[string]any{
    "model": "anthropic/claude-haiku-4-5",
    "max_tokens": 128,
    "messages": []map[string]any{{"role": "user", "content": "Hello"}},
})
if err != nil { return err }
var message struct { ID string `json:"id"` }
if err = json.Unmarshal(raw, &message); err != nil { return err }
_, err = client.VerifyResponse(ctx, message.ID)
```

For streaming, POST to `client.BaseURL()+"messages"` through `client.HTTPClient()`
with `"stream": true`. Consume and close the body before verification. Configure
custom Anthropic headers on the request or in `ClientOptions.Headers`.
See the [native example](../../examples/example-go/gateway/messages/main.go).

The official Anthropic Go SDK can use
`option.WithHTTPClient(client.HTTPClient())` and `option.WithMaxRetries(0)`.
Set its base URL to the API root, such as `https://cloud-api.near.ai`, because it
appends `/v1/messages`. The inference client's base URL includes `/v1/`.
The [official SDK example](../../examples/example-go/gateway/messages-with-anthropic-sdk/main.go)
covers JSON and streaming, then verifies each response before printing it.

## Responses API

Gateway clients support Responses creation as JSON or SSE, with optional OHTTP
(Ed25519). Use field-level E2EE disabled.

Verify the response `id` after reading a JSON response, or `event.response.id`
after consuming the stream. Responses use Gateway receipts.

```go
body, err := client.CreateResponse(ctx, map[string]any{
    "model": "z-ai/glm-5.3-flash", "input": "Reply with the word ok.", "store": false,
})
if err != nil { return err }
var response struct { ID string `json:"id"` }
if err := json.Unmarshal(body, &response); err != nil { return err }
receipt, err := client.VerifyResponse(ctx, response.ID)
```

For typed JSON or SSE, use the official OpenAI Go client with
`option.WithHTTPClient(client.HTTPClient())` and
`option.WithBaseURL(client.BaseURL())`. Call `Responses.New` or
`Responses.NewStreaming`; finish iteration and check `stream.Err()` before
verifying `event.Response.ID` from a response lifecycle event.

## Configure verification and deployment policies

The default policy accepts `UpToDate`, `OutOfDate`, and `TDRelaunchAdvised` TCB
statuses, rejects debug quotes, and verifies GPU evidence when present. Require
stricter status and GPU policies through `ModelVerification` (or
`GatewayVerification` where appropriate):

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

Pass these options to `NewInferenceClient`.

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
[image provenance API](./api-reference.md#image-provenance-api) for policy configuration.
The `imagePolicy` helper applies only to `options.DeploymentPolicy`, which runs
for model deployments. Gateway verification uses a callback without a model
argument. Use a separate helper for `options.GatewayVerification.DeploymentVerifier`:

```go
func gatewayImagePolicy(
	policies map[string]nearai.ImageProvenancePolicy,
	provenance nearai.ProvenanceOptions,
) nearai.DeploymentVerifier {
	return func(ctx context.Context, deployment nearai.MeasuredDeployment) error {
		return nearai.VerifyDeploymentImageProvenance(
			ctx, deployment.AppCompose, policies, provenance,
		)
	}
}
```

Use separate callbacks for model and Gateway image policies.

## Images deployed by Compose Manager

Use a model deployment callback to require authenticated deployment actions and
published-image provenance. The compose file and manager have independent policies:

```go
modelImages := map[string]nearai.ImageProvenancePolicy{
    "nearaidev/vllm-proxy-rs": {
        Repository: "nearai/inference-proxy", Workflow: ".github/workflows/build.yml",
    },
}
check := func(ctx context.Context, deployment nearai.MeasuredDeployment) error {
    return nearai.VerifyComposeManagerDeploymentImageProvenance(ctx, deployment, modelImages,
        nearai.ComposeManagerDeploymentImageProvenanceOptions{
            ComposeManagerImagePolicy: nearai.ComposeManagerImagePolicy{
                ImageRepository: "nearaidev/compose-manager",
                Build: nearai.ImageProvenancePolicy{
                    Repository: "nearai/compose-manager", Workflow: ".github/workflows/build.yml",
                },
            },
        })
}
// Gateway and Direct: ModelVerification: nearai.VerificationOptions{DeploymentVerifier: check}
```

This checks container image builds recorded by Compose Manager. Set source
commit or ref pins to restrict accepted builds. See the
[API reference](./api-reference.md#compose-manager-deployment-provenance) for file
selection and GitHub access options.

## Configure attestation service URLs

The built-in verifiers use these defaults:

| Service | URL |
| --- | --- |
| PCCS base | `https://api.trustedservices.intel.com` |
| NRAS evidence | `https://nras.attestation.nvidia.com/v3/attest/gpu` |
| NVIDIA signing keys | `https://nras.attestation.nvidia.com/.well-known/jwks.json` |

To use your own services, configure the verifier callbacks:

```go
verifiers := nearai.VerificationOptions{
    QuoteVerifier: nearai.CreateTDXQuoteVerifier("https://attestation.example.com/pccs"),
    GPUVerifier: nearai.CreateGPUEvidenceVerifier(nearai.GPUVerifierOptions{
        NRASURL: "https://attestation.example.com/nras/v3/attest/gpu",
    }),
}
```

Pass these options to model verification; Gateway verification uses the same
quote callback. DCAP builds the SGX and TDX collateral paths beneath the PCCS
base URL. `NRASURL` is the complete GPU evidence POST URL. Signing keys come
from NVIDIA; set `JWKSURL` separately to use another trusted key source.

## Encryption and TLS binding

E2EE requests use `X-Encryption-Version: 3`, binding the reply public key and
field label through authenticated data. The endpoint must support v3. See the
[wire protocol](https://github.com/nearai/inference-proxy/blob/main/docs/e2ee.md)
for the format and supported fields.

Enable `E2EE: true` to encrypt supported content fields to an attested model key.
Enable `OHTTP: true` to encrypt encapsulated requests and responses to the Gateway
or Direct endpoint. `Authorization` and configured forwarded headers remain on
the outer HTTP request. OHTTP requires Ed25519 and can be combined with E2EE. See the
[encryption reference](./api-reference.md#encryption) for exact field coverage.

Gateway requests use attested TLS pinning by default. For an application proxy,
set `DisableTLSBinding: true`.

## Experimental direct endpoints

Direct clients require an explicit model endpoint URL. E2EE is disabled by
default; this example enables it:

```go
client, err := nearai.NewDirectInferenceClient(nearai.DirectInferenceOptions{
	ClientOptions: nearai.ClientOptions{
		APIKey:  apiKey,
		BaseURL: directBaseURL,
	},
	E2EE: true,
})
if err != nil {
	return err
}
defer client.Close()
```

`DirectInferenceClient` connects to a model endpoint and verifies every returned
model report. It supports Chat, streaming, OHTTP, and OpenAI integration.
Requests use the verified model TLS fingerprints by default.

`VerifyResponse` returns `VerifiedDirectCompletionResult` with all matching model
reports in `Attestations`. After `VerifyDirectModelAttestations`, create a pinned
transport with `NewPinnedTransport(transport, verified.SPKIFingerprints...)`.
Wrap it in `httpClient := &http.Client{Transport: pinned}`. Use that client for
Chat and pass it to `NewDirectAttestationClient` via `ClientOptions.HTTPClient`
to fetch the response signature.

## Manual verification

For applications that own HTTP requests, use the standalone APIs in this order:

1. Create an `AttestationClient` and fetch Gateway evidence with a fresh binding.
2. Authenticate the report with `VerifyGatewayAttestation`.
3. Build a pinned transport with `NewPinnedTransport` using the verified Gateway
   fingerprint. Use the pinned HTTP client for Chat and as `ClientOptions.HTTPClient`
   when fetching model evidence or signatures.
4. Fetch model evidence and verify every returned report with
   `VerifyModelAttestation`, applying your deployment policy.
5. If encrypting manually, pass a verified model key to `PrepareE2EEChatRequest`.
   Retain the exact encrypted request and response bytes before decrypting.
6. Fetch the completion signature and verify its kind with `VerifyModelResponse`
   or `VerifyGatewayResponse` against the corresponding authenticated evidence.

For example, this Gateway preflight rebuilds the evidence client after pinning.
Add `"net/http"` to your imports:

```go
func manualPreflight(ctx context.Context, opts nearai.ClientOptions, model string) error {
	api, err := nearai.NewAttestationClient(opts)
	if err != nil {
		return err
	}
	fetch := nearai.FetchOptions{SigningAlgo: nearai.Ed25519}
	fetched, err := api.FetchGatewayAttestation(ctx, fetch)
	if err != nil {
		return err
	}
	gateway, err := nearai.VerifyGatewayAttestation(
		ctx, fetched.Attestation, fetched.ClientBinding, nearai.VerificationOptions{},
	)
	if err != nil {
		return err
	}

	pinned, err := nearai.NewPinnedTransport(nil, gateway.SPKIFingerprint)
	if err != nil {
		return err
	}
	defer pinned.CloseIdleConnections()

	opts.HTTPClient = &http.Client{
		Transport: pinned,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	api, err = nearai.NewAttestationClient(opts)
	if err != nil {
		return err
	}
	models, err := api.FetchModelAttestations(ctx, model, fetch)
	if err != nil {
		return err
	}
	for _, report := range models.Attestations {
		if _, err := nearai.VerifyModelAttestation(
			ctx, report, models.ClientBinding, nearai.VerificationOptions{},
		); err != nil {
			return err
		}
	}

	// Continue here using opts.HTTPClient for Chat and the rebuilt api for
	// FetchCompletionSignature. Keep the verified evidence and exact wire bytes.
	return nil
}
```

This preflight demonstrates transport setup; the bare examples include Chat,
encryption, response signatures, and application deployment policies.

Keep the exact encrypted request and response bytes for signature verification.
See the [bare examples](../../examples/example-go/README.md) for the complete flow.

`provider_tee` receipts verify a model signature; `gateway` receipts verify a
Gateway signature over the request and response bytes.

## Retention and lifecycle

Reuse the client across requests and close it when finished. Close each response body.

Set `AttestationTTL` to control deployment verification reuse; a pointer to zero
verifies every request. Verify responses before `ResponseTTL` expires.
Both default to one hour.

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

If signature retrieval fails transiently, retry `VerifyResponse` for the existing completion.
