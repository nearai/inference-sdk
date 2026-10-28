# Go verification guide

Use the Go SDK to verify deployments before sending a prompt and explicitly
verify response signatures after receiving a completion. This guide covers
Gateway clients, the official OpenAI Go client, streaming, policies, encryption,
and experimental direct endpoints. See the [API reference](./api-reference.md)
for signatures, options, and result fields.

## Install

Requires Go 1.26.10 or later. In your Go module:

```sh
go get github.com/nearai/inference-sdk/go@v0.1.0
```

Set `NEARAI_API_KEY` for the examples below. The SDK itself takes credentials
explicitly. Choose a model available to your account; E2EE requires a model with
supported attestation and encryption keys.

## Send and verify a completion

The client first verifies Gateway evidence without authentication headers, including
the OHTTP key configuration when OHTTP is enabled. It then uses configured
authentication to fetch metadata and model reports before sending Chat.
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

`Verify` shares Chat and System One's cache and in-flight work without sending
an inference request. Cached evidence keeps its original verification timestamp. Every
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

You can display chunks immediately, but that output is not signature-verified
until `VerifyResponse` succeeds. Close abandoned streams to cancel their requests.
Incomplete or failed bodies cannot be verified later. With raw `net/http`, consume
the response body through EOF and close it; SSE events may span multiple reads.

## Verify System One decisions

Create a Gateway client with E2EE and OHTTP disabled. Send structured questions
with `client.CreateSystemOne(ctx, request)`, then call
`client.VerifyResponse(ctx, result.DecisionID)` before using `result.Data.Answers`.

Self-hosted models use `x-model-pub-key` routing and verify the response against
the selected model signer, as Chat does. The endpoint must support this routing.
External models use Gateway signatures.

The [API reference](./api-reference.md#system-one-decisions) describes request
and result types. To try a complete application, run the
[decision example](../../examples/example-go/gateway/systemone/main.go).

## Messages API

The Gateway client supports `POST /v1/messages` with attestation preflight,
TLS binding where available, and optional OHTTP (Ed25519). Requests preserve
Anthropic system/content blocks, tools, tool results, and other JSON fields;
available features depend on the Gateway and model. `anthropic-version` and
`anthropic-beta` headers are preserved. The built-in interface defaults to
`anthropic-version: 2023-06-01`.

Verify the top-level message `id` after JSON consumption, or
`message_start.message.id` after consuming the complete SSE stream through
`message_stop`. Tool-use IDs and the billing `Inference-Id` header are separate.
Verification uses the original request and response bytes and requires a
`gateway` receipt. This authenticates the Gateway's observation, not external
Anthropic model execution inside a TEE. Failed, incomplete, and cancelled streams
cannot yield a verified complete response. If receipt lookup is temporarily
unavailable, retry verification without sending inference again.

Messages field-level E2EE and Direct clients are rejected before network I/O,
matching the server's supported contract. Only Messages creation is supported.

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
The [official SDK example](../../examples/example-go/gateway/anthropic/main.go)
covers JSON and streaming, then verifies each response before printing it.

## Responses API

The Gateway client supports `POST /v1/responses` with the same authentication,
attestation preflight, TLS settings, and optional OHTTP as Chat. It preserves
input items, function tools, reasoning fields, and output events. The SDK forwards
`store: false` unchanged; stateless behavior is provided by the server. For
client-managed context, replay function calls with their matching outputs in
subsequent requests. Available features depend on the server and model.

Responses receipts must have `signature_kind: gateway`: they authenticate the
Gateway's exact request/response bytes, not a model signature over the final
Responses object. Receipt persistence is best-effort. A successful inference can
still have an unavailable receipt; retry receipt lookup when appropriate without
repeating inference. Consume the entire SSE stream before verifying its nested
`event.response.id`; output item IDs are not receipt IDs.

Field-level E2EE and Direct Responses are rejected before network I/O. OHTTP is
supported with Ed25519. Provider `reasoning.encrypted_content` is passed through
as opaque data and is separate from NEAR field encryption. Only creation is
supported; response retrieval, cancellation, deletion, and history endpoints are
outside this transport.

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

Configure the two callbacks with separate model and Gateway image policies.
`DeploymentPolicy` is not applied to Gateway evidence.

Custom quote, GPU, and deployment verifiers are trusted application code. They
must authenticate evidence, rather than merely parse it.

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

The policy runs for every model report and requires Compose Manager evidence in
each one. Pin source commits or refs according to your release policy. The evidence
covers recorded deployment actions and image builds. Current runtime state
requires separate evidence. See the [API reference](./api-reference.md#compose-manager-deployment-provenance)
for file selection and GitHub access.

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

Direct clients require an explicit model endpoint URL. E2EE is disabled by
default; this example enables it:

```go
client, err := nearai.NewDirectInferenceClient(nearai.DirectInferenceOptions{
	InferenceOptions: nearai.InferenceOptions{
		ClientOptions: nearai.ClientOptions{
			APIKey:  apiKey,
			BaseURL: directBaseURL,
		},
		E2EE: true,
	},
})
if err != nil {
	return err
}
defer client.Close()
```

The Chat, OpenAI adapter, streaming, and `VerifyResponse` APIs are the same.
Use `E2EE` to configure encryption; `DisableE2EE` is deprecated. Direct clients omit
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
   fingerprint. Rebuild the attestation client with that transport before fetching
   model evidence or signatures; creating a pinned transport does not modify the
   original client. Use the pinned HTTP client for Chat as well.
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
verification. Expired receipts cannot be verified. See
[client lifecycle](./api-reference.md#clients-and-lifecycle) for retention behavior.

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
