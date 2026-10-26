# NEAR AI Inference SDK for Go

Verified OpenAI-compatible Chat Completions for Go applications.
The client verifies Gateway and model deployments before sending prompts,
optionally encrypts requests, and retains exact bytes for explicit response
signature verification.

## Build and install

Requires Go **1.26.10+**. The module includes the pinned DCAP verifier as an
embedded WebAssembly artifact, executed locally with wazero. Users do not need
Rust, CGO, a C compiler, a native library, or linker environment variables.
There is no Node.js or Python runtime dependency. `CGO_ENABLED=0` and ordinary
Go cross-compilation are supported; CI tests Linux and macOS.

From a checkout, run the SDK tests with:

```sh
cd go
CGO_ENABLED=0 go test ./...
```

Race tests use `go test -race ./...` and require CGO for Go's race detector only;
the SDK itself does not require CGO. See [the verifier notes](./internal/dcap/README.md)
for provenance, resource limits, and the maintainer-only artifact rebuild.

Install the released SDK in your Go project:

```sh
go get github.com/nearai/inference-sdk/go@v0.1.0
```

Go module releases use `go/vX.Y.Z` repository tags. See the
[release process](../RELEASING.md#go-module) for maintainer instructions.

## Send and verify a completion

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
        E2EE: true,
    })
    if err != nil {
        return err
    }
    defer client.Close()

    body, err := client.CreateChatCompletion(ctx, map[string]any{
        "model": "z-ai/glm-5.3-flash",
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

Import as `nearai "github.com/nearai/inference-sdk/go"`. The
[OpenAI example](../examples/example-go/gateway/openai/main.go) uses the official OpenAI Go
SDK and reads `NEARAI_API_KEY` from the environment. It covers JSON and streaming calls. See the [Gateway/direct
examples](../examples/example-go/README.md) for standalone and integrated clients,
Gateway image provenance, and exact ciphertext receipt verification. The library
itself takes credentials explicitly.

## Use an existing OpenAI Go client

`InferenceClient` implements `http.RoundTripper`. Configure the official SDK
with its HTTP adapter and disable automatic completion retries:

```go
ai := openai.NewClient(
    option.WithAPIKey(apiKey),
    option.WithBaseURL(client.BaseURL()),
    option.WithHTTPClient(client.HTTPClient()),
    option.WithMaxRetries(0),
)
```

Both `ai.Chat.Completions.New` and `NewStreaming` use the verified transport.
Consume the stream to completion, check `stream.Err()`, close it, then call
`client.VerifyResponse(ctx, completionID)`. Output shown before verification
succeeds is not yet signature-verified. Close an abandoned stream to cancel its
request; incomplete or failed streams are not registered for verification.

The [direct OpenAI example](../examples/example-go/direct/openai/main.go) uses
`NewDirectInferenceClient` with the same OpenAI HTTP adapter for encrypted JSON
and streaming Chat. Direct endpoints are experimental: they omit Gateway
verification and do not bind direct TLS identity to attestation. Normal HTTPS
validation remains enabled. Use Gateway clients for production.

The Gateway adapter accepts POSTs to its configured `chat/completions` and
`responses` and `messages` endpoints. See [Responses](./docs/verification-guide.md#responses-api)
and [Messages](./docs/verification-guide.md#messages-api)
for JSON, SSE, and Gateway receipt verification.
Use `AttestationClient` for metadata and evidence. Arbitrary/future Chat fields
are preserved; the SDK encrypts only the documented protocol fields.

## Features and defaults

| Feature | Go API | Default |
| --- | --- | --- |
| Gateway and model attestation | `Verify`, standalone verification functions | Enabled before Chat |
| Intel TDX/DCAP and NVIDIA NRAS | Default verifiers, configurable hooks | Enabled; GPU evidence checked when supplied |
| Attested Gateway TLS pinning | `NewPinnedTransport`, inference client | Enabled |
| Exact response signatures | `VerifyResponse`, `VerifyModelResponse`, `VerifyGatewayResponse` | Explicit call |
| JSON and streaming Chat | `CreateChatCompletion`, `HTTPClient` | Both supported |
| Ed25519 and ECDSA | `SigningAlgo` | Ed25519 |
| Field E2EE | `E2EE`, `PrepareE2EEChatRequest` | Off; set `E2EE: true` to enable |
| Chunked OHTTP / BHTTP | `OHTTP`, `NewOHTTPTransport`, `VerifyOHTTPKeyConfig` | Off; requires Ed25519 |
| Deployment preflight/cache | `Verify`, `AttestationTTL` | One hour; shared in-flight verification |
| Retained response records | `ResponseTTL` | One hour from full body consumption |
| Deployment admission policy | `DeploymentPolicy`, `VerificationOptions` | Caller supplied |
| GitHub/Sigstore image provenance | `FetchImageProvenance`, `VerifyImageProvenance`, `VerifyDeploymentImageProvenance` | Caller supplied |
| Direct endpoints | `NewDirectInferenceClient`, `NewDirectAttestationClient` | Experimental |

Go uses contexts, `net/http`, structured errors, and standard streams rather
than the asynchronous object APIs of JavaScript/Python. It has the same protocol
features; it does not expose a browser transport. See the
[verification guide](./docs/verification-guide.md) and
[API reference](./docs/api-reference.md) for trust boundaries and integration details.

The [live suite](../e2e/README.md) covers staging and production Gateway APIs,
including both signing algorithms, JSON/SSE, E2EE, OHTTP, and the official OpenAI
client. Live tests require the `e2e` build tag and credentials.

No authenticated live inference is required by the unit tests. They use local
servers, shared encryption vectors, signed Sigstore fixtures, and an offline
Intel-signed quote with its collateral.

## Verification and privacy

Deployment verification runs before Chat requests. Response signatures require
an explicit `VerifyResponse` call after fully consuming the body. For streaming,
content displayed before that call succeeds has not yet been signature-verified.
All returned model reports must pass verification; failed verification does not
silently downgrade to an unverified request.

`E2EE` encrypts protocol fields to the attested model key. `OHTTP` independently
protects the inner request to the Gateway and requires Ed25519. Gateway-only
`Incognito` also requires E2EE and supported model metadata. See the
[encryption notes](./docs/api-reference.md#encryption) for the exact guarantees.

A `provider_tee` receipt binds exact request/response bytes to the model signer;
a Gateway receipt binds its own bytes to the Gateway signer. These receipts do
not prove an end-to-end cryptographic chain through every intermediary
transformation. Deployment verification also does not apply an application
image allowlist unless you configure a policy. See
[verification guarantees](./docs/api-reference.md#verification-guarantees) and
[deployment policies](./docs/api-reference.md#deployment-and-image-policies).

## Retention and errors

Attestation and response caches default to one hour. Response retention starts
when the body is fully consumed. Set a TTL to a pointer to `time.Duration(0)`
to disable reuse or retention. Expired response records cannot be verified later.
Cache memory grows with retained responses; choose a TTL appropriate for your
workload. See [client lifecycle](./docs/api-reference.md#clients-and-lifecycle).

`MaxBodyBytes` defaults to 64 MiB per request/response. Buffered protected
requests honor the configured body limit.

Errors support `errors.As` into `*nearai.Error`, exposing `Code` and `Retryable`.
Retryable receipt retrieval can be attempted again without replaying Chat.
The SDK does not automatically replay completions.

## Advanced APIs and documentation

Use `NewAttestationClient` to fetch evidence and standalone verification
functions to validate it. Fetching evidence alone does not verify it.
`PrepareE2EEChatRequest` supports manual encryption after authenticating the
model key; standalone encryption and OHTTP helpers use a 64 MiB body limit.
Keep exact wire bytes when verifying receipts manually.

- [Verification guide](./docs/verification-guide.md)
- [API reference](./docs/api-reference.md)
- [Gateway, direct, and OpenAI examples](../examples/example-go/README.md)
- [Live E2E coverage](../e2e/README.md)
- [Release process](../RELEASING.md)

## Development

From the repository root:

```sh
make -C go check
cd examples/example-go
go test -race ./...
```

`make -C go check` checks formatting, runs vet, and executes race tests. Race
instrumentation requires CGO; ordinary SDK builds and tests support
`CGO_ENABLED=0`.
