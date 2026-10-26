# Go examples

Use Go 1.26.10+ as described in [the Go SDK README](../../go/README.md).
The DCAP verifier is embedded; no Rust, native library, or linker setup is required. Set `NEARAI_API_KEY` through your secret manager or shell.

Run from this directory:

| Command | Demonstrates |
| --- | --- |
| `go run ./gateway/openai` | [Official OpenAI Go SDK](https://github.com/openai/openai-go), JSON and streaming, E2EE, verified transport and receipts |
| `go run ./gateway/anthropic` | Official Anthropic Go SDK, Messages JSON/SSE, verified transport and Gateway receipts |
| `go run ./gateway/messages` | Native Messages JSON/SSE and Gateway receipts |
| `go run ./gateway/systemone` | Structured decisions with verified receipts |
| `go run ./gateway/client` | Integrated Gateway preflight, E2EE, JSON/SSE, image provenance and receipts |
| `go run ./gateway/bare` | Standalone Gateway/model verification, pinned TLS, E2EE, ciphertext capture/decryption and receipts |
| `go run ./direct/openai` | Experimental official OpenAI Go client through the direct verified transport, E2EE, JSON/SSE, and receipts. |
| `go run ./direct/client` | Experimental integrated direct inference, JSON/SSE, E2EE and receipts |
| `go run ./direct/bare` | Standalone direct report verification, E2EE, ciphertext capture/decryption and all matching receipt signers |

## System One decisions

Set `NEARAI_SYSTEMONE_MODEL` to a decision model from your endpoint's catalog.
`NEARAI_API_KEY` supplies the credential and `NEARAI_BASE_URL` selects the endpoint.
Run `go run ./gateway/systemone` to send a question and print its verified answer.
See the [guide](../../go/docs/verification-guide.md#verify-system-one-decisions) for API usage.

## Official Anthropic Go client

The [Messages example](./gateway/anthropic/main.go) injects
`inference.HTTPClient()` into the official client and disables automatic inference
retries. It sends JSON and SSE requests and verifies Gateway receipts before
printing either answer. `NEARAI_BASE_URL` selects the Gateway's `/v1/` URL,
`NEARAI_MODEL` defaults to `anthropic/claude-haiku-4-5`, and `NEARAI_OHTTP=true`
enables OHTTP with Ed25519. See the [Messages guide](../../go/docs/verification-guide.md#messages-api).

## Official OpenAI Go client

The named entry point is [gateway/openai/main.go](./gateway/openai/main.go).
`go run .` remains an alias for the same example. Both call
[`RunOpenAI`](./internal/demo/demo.go), which configures the official client with
`option.WithHTTPClient(client.HTTPClient())` and disables automatic completion
retries with `option.WithMaxRetries(0)`.

The example sends JSON and streaming Chat with E2EE. It consumes streams through
EOF and calls `client.VerifyResponse(ctx, completionID)` before displaying the
answer. The Gateway transport also supports
[Responses creation](../../go/docs/verification-guide.md#responses-api) with E2EE
disabled. Local integration tests and the live `TestLiveOpenAI` case cover
both JSON and streaming through the Gateway implementation. Local adapter tests
also exercise direct JSON/SSE with signed provider receipts; the live suite does
not test experimental direct endpoints.

For an experimental direct endpoint, use [direct/openai/main.go](./direct/openai/main.go)
with `go run ./direct/openai`. It calls `RunDirectOpenAI`, selects
`NewDirectInferenceClient`, and uses the same JSON/SSE and receipt-verification
workflow as the Gateway example. E2EE is enabled. Set `NEARAI_BASE_URL`,
`NEARAI_MODEL`, and an endpoint-accepted `NEARAI_API_KEY` for your direct deployment.
It verifies model reports and provider receipts without Gateway verification;
direct TLS fingerprint binding remains disabled, while normal HTTPS validation
still applies. Use the Gateway example for production.

`NEARAI_BASE_URL` and `NEARAI_MODEL` override the Gateway/direct defaults.
`NEARAI_SIGNING_ALGO` accepts `ed25519` (default) or `ecdsa` and selects the same
algorithm for evidence, encryption, and receipt lookup. Use a NEAR TEE model for E2EE.
Run direct examples separately with the matching direct URL and model; direct
endpoints remain experimental and do not authenticate TLS with attestation.

The Chat examples consume both JSON and SSE through HTTP EOF and verify
receipts before displaying plaintext. Standalone examples capture ciphertext
below decryption; they never verify a signature over reserialized plaintext.
Direct verification returns every report sharing the response signer, rather
than claiming a particular serving instance.

Gateway examples use the same four image provenance policies as JavaScript and
Python: `cloud-api`, `cvm-ingress`, `dstack-vpc`, and `dstack-vpc-client`. These
policies cover Gateway build artifacts, not model runtime images or weights.
Add commit pins in `internal/demo.GatewayImages` for stricter admission policy.
An optional `GITHUB_TOKEN` increases GitHub API rate limits for provenance lookup.

`go vet ./...` and `go test -race ./...` compile every example and exercise the
OpenAI transport with local signed fixtures. Live OpenAI JSON/SSE coverage is
opt-in: `go test -tags=e2e -run '^TestLiveOpenAI$' -v .`, with the shared live
configuration from [the E2E guide](../../e2e/README.md).
