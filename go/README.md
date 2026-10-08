# NEAR AI Inference SDK for Go

Verified OpenAI-compatible Chat Completions for Go services and tools such as
[Open Code Review](https://github.com/think-in-universe/open-code-review/pull/1).
The client verifies Gateway and model deployments before sending prompts,
optionally encrypts requests, and retains exact bytes for explicit response
signature verification.

## Build and install

Requires Go **1.25.8+**, CGO, a C compiler, and the native DCAP QVL static library.
There is no Node.js or Python runtime dependency. The supported native build
platforms are Linux and macOS on amd64/arm64. Cross-compilation requires a native
library and C toolchain for the target; `CGO_ENABLED=0` is not supported.

From a checkout of this repository, install a current stable Rust toolchain and
build the pinned DCAP QVL source once:

```sh
cd go
DCAP_LIBRARY_DIR="$(./scripts/build-dcap.sh)"
export CGO_LDFLAGS="-L$DCAP_LIBRARY_DIR"
go test -race ./...
```

Keep `CGO_LDFLAGS` set when building programs using the SDK. Rust is needed to
build the library, not to run a compiled Go program. The script uses an external
cache and checks the source revision; no binary is downloaded or committed.
See [the adapter notes](./internal/dcap/README.md) for provenance and local fixes.

This module has no Go release tag yet. For local integration, use a replacement:

```sh
go mod edit -require=github.com/nearai/inference-sdk/go@v0.0.0
go mod edit -replace=github.com/nearai/inference-sdk/go=/absolute/path/to/inference-sdk/go
go mod tidy
```

After this PR merges, `go get github.com/nearai/inference-sdk/go@main` can resolve
a pseudo-version. A future module release uses a `go/vX.Y.Z` tag.

## Send and verify a completion

```go
client, err := nearai.NewInferenceClient(nearai.InferenceOptions{
    ClientOptions: nearai.ClientOptions{APIKey: os.Getenv("NEARAI_API_KEY")},
    E2EE: true,
})
if err != nil { return err }
defer client.Close()

body, err := client.CreateChatCompletion(ctx, map[string]any{
    "model": "z-ai/glm-5.3-flash",
    "messages": []map[string]string{{"role": "user", "content": "Hello!"}},
})
if err != nil { return err }
var completion struct { ID string `json:"id"` }
if err := json.Unmarshal(body, &completion); err != nil { return err }
verified, err := client.VerifyResponse(ctx, completion.ID)
if err != nil { return err }
fmt.Println(verified.SignatureKind)
fmt.Println(string(body))
```

Import as `nearai "github.com/nearai/inference-sdk/go"`. The
[runnable example](../examples/example-go/main.go) uses the official OpenAI Go
SDK and accepts either `NEARAI_API_KEY` or OCR's `NEAR_AI_API_KEY` environment
variable. The library itself takes credentials explicitly.

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

The adapter only accepts POSTs to its configured `chat/completions` endpoint.
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
| Field E2EE | `E2EE`, `PrepareE2EEChatRequest` | Off for Gateway; on for direct clients |
| Chunked OHTTP / BHTTP | `OHTTP`, `NewOHTTPTransport`, `VerifyOHTTPKeyConfig` | Off; requires Ed25519 |
| Deployment preflight/cache | `Verify`, `AttestationTTL` | One hour; shared in-flight verification |
| Retained response records | `ResponseTTL` | One hour from full body consumption |
| Deployment admission policy | `DeploymentPolicy`, `VerificationOptions` | Caller supplied |
| GitHub/Sigstore image provenance | `FetchImageProvenance`, `VerifyImageProvenance`, `VerifyDeploymentImageProvenance` | Caller supplied |
| Direct endpoints | `NewDirectInferenceClient`, `NewDirectAttestationClient` | Experimental |

Go uses contexts, `net/http`, structured errors, and standard streams rather
than the asynchronous object APIs of JavaScript/Python. It has the same protocol
features; it does not expose a browser transport. See [API and verification
notes](./docs/api-reference.md) for trust boundaries and integration details.

No authenticated live inference is required by the unit tests. They use local
servers, shared encryption vectors, signed Sigstore fixtures, and an offline
Intel-signed quote with its collateral.
