# NEAR AI Inference SDK examples

These examples verify deployment evidence before inference and verify the exact
request/response bytes against the response receipt. JSON answers are printed
after verification. SSE text is printed as it arrives, then the receipt is verified
after the stream finishes; verification failures exit with an error.

## Configuration

All four languages use the same environment variables:

| Variable | Meaning and default |
| --- | --- |
| `NEARAI_API_KEY` | Required credential for the selected endpoint |
| `NEARAI_BASE_URL` | Gateway: `https://cloud-api.near.ai/v1/`; direct: `https://glm-5-3-flash.completions.near.ai/v1/` |
| `NEARAI_MODEL` | Chat/Responses: `z-ai/glm-5.3-flash`; Messages: `anthropic/claude-haiku-4-5`; required for System One |
| `NEARAI_SIGNING_ALGO` | `ed25519` (default) or `ecdsa`, used for evidence and receipts, and for Chat E2EE |
| `NEARAI_OHTTP` | `true` enables OHTTP for integrated Chat, Responses, and Messages clients; requires Ed25519 |
| `NEARAI_EXPECT_SIGNATURE_KIND` | System One: `gateway` (default) or `provider_tee`; the latter requires verified model evidence |
| `NEARAI_IMAGE_PATH` | Optional PNG file path for the native System One image/Box example |
| `GITHUB_TOKEN` | Optional GitHub token for image provenance requests in native and standalone Gateway Chat examples |

Choose a model available in the selected endpoint's catalog. Chat client examples
and the standalone Gateway Chat examples explicitly enable field-level E2EE;
use a NEAR TEE model for those examples. Responses, Messages, and System One keep
E2EE disabled. OHTTP is independent of E2EE and requires signed key configuration
and an `/ohttp` endpoint. System One uses neither E2EE nor OHTTP.

Bare Gateway Chat examples verify deployments, send Chat through pinned TLS,
and verify the response signature using the exact encrypted bytes.

Bare Chat examples display the preflight report count and the number of reports
matching the response signer. Use these collections to display individual reports.

## Entry points

Each Chat, Responses, and Messages entry point runs JSON and SSE. Commands below
run from `examples/example-js`, `examples/example-py`, `examples/example-rs`, or
`examples/example-go`, respectively.

Entry points are grouped under `gateway/` and `direct/` (`src/gateway/` and
`src/direct/` in Rust). All languages share the entry-point names
`chat-completions`, `systemone`, `messages`, and `responses`. Standalone verification
adds `-bare`; official SDK integrations add `-with-<vendor>-sdk`. Python and Rust source filenames use
underscores in place of hyphens.

| Capability | JavaScript | Python | Rust | Go |
| --- | --- | --- | --- | --- |
| Gateway Chat, native client | `node gateway/chat-completions.ts` | `uv run python -m gateway.chat_completions` | `cargo run --bin gateway-chat-completions` | `go run ./gateway/chat-completions` |
| Gateway Chat, standalone verification | `node gateway/chat-completions-bare.ts` | `uv run python -m gateway.chat_completions_bare` | `cargo run --bin gateway-chat-completions-bare` | `go run ./gateway/chat-completions-bare` |
| Gateway Chat, official OpenAI SDK | `node gateway/chat-completions-with-openai-sdk.ts` | `uv run python -m gateway.chat_completions_with_openai_sdk` | — | `go run ./gateway/chat-completions-with-openai-sdk` |
| Responses, native client | `node gateway/responses.ts` | `uv run python -m gateway.responses` | `cargo run --bin responses` | `go run ./gateway/responses` |
| Responses, official OpenAI SDK | `node gateway/responses-with-openai-sdk.ts` | `uv run python -m gateway.responses_with_openai_sdk` | — | `go run ./gateway/responses-with-openai-sdk` |
| Messages, native client | `node gateway/messages.ts` | `uv run python -m gateway.messages` | `cargo run --bin messages` | `go run ./gateway/messages` |
| Messages, official Anthropic SDK | `node gateway/messages-with-anthropic-sdk.ts` | `uv run python -m gateway.messages_with_anthropic_sdk` | — | `go run ./gateway/messages-with-anthropic-sdk` |
| System One, native client | `node gateway/systemone.ts` | `uv run python -m gateway.systemone` | `cargo run --bin systemone` | `go run ./gateway/systemone` |
| System One, official TypeSafe SDK | `node gateway/systemone-with-typesafe-sdk.ts` | `uv run python -m gateway.systemone_with_typesafe_sdk` | — | — |
| Direct Chat, native client | `node direct/chat-completions.ts` | `uv run python -m direct.chat_completions` | `cargo run --bin direct-chat-completions` | `go run ./direct/chat-completions` |
| Direct Chat, standalone verification | `node direct/chat-completions-bare.ts` | `uv run python -m direct.chat_completions_bare` | `cargo run --bin direct-chat-completions-bare` | `go run ./direct/chat-completions-bare` |
| Direct Chat, official OpenAI SDK | `node direct/chat-completions-with-openai-sdk.ts` | `uv run python -m direct.chat_completions_with_openai_sdk` | — | `go run ./direct/chat-completions-with-openai-sdk` |

Official SDK examples use the inference client's HTTP transport and response
verification. System One examples print verified decision answers.

### System One images

The native System One examples in all four languages can locate the main object
in a PNG. Select a Box-capable model from your Gateway's catalog, such as Jev 1.14,
and set the image path before running the native System One command above:

```sh
export NEARAI_MODEL=typesafe/jev-1.14
export NEARAI_IMAGE_PATH=/absolute/path/to/photo.png
```

The example sends an `image_url` JSON part and a `box` question, then prints the
coordinates and confidence after verifying the receipt. Unset `NEARAI_IMAGE_PATH`
to run the text example.

### JavaScript setup

Requires Node.js 24.22.1+. Build the local SDK before running examples:

```sh
pnpm --dir js install --frozen-lockfile
pnpm --dir js build
pnpm --dir examples/example-js install --frozen-lockfile
cd examples/example-js
node gateway/chat-completions.ts
```

Package scripts are also available, such as `pnpm start:chat-completions`.

### Python setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). The example project
imports the sibling Python SDK through an editable path dependency.

```sh
cd examples/example-py
uv sync --locked
uv run python -m gateway.chat_completions
```

Run Python examples as modules from this directory so they can import the
shared `utils` package.

### Rust setup

The examples use the sibling Rust SDK through a path dependency. See the
[Rust build requirements](../rs/README.md).

```sh
cd examples/example-rs
cargo run --locked --bin gateway-chat-completions
```

### Go setup

Requires Go 1.26.10+. The SDK embeds the DCAP verifier. The example module
replaces the SDK dependency with the sibling source.

```sh
cd examples/example-go
go run ./gateway/chat-completions-with-openai-sdk
```

Replace local path dependencies with released packages when copying an example
out of this repository.

## Shared helpers and tests

Keep reusable example code in each language's helper directory:

| Language | Helpers | Offline tests |
| --- | --- | --- |
| JavaScript | `example-js/utils/` | `example-js/tests/`; run `pnpm check` |
| Python | `example-py/utils/` | `example-py/tests/`; run `uv run python -m unittest discover -s tests` |
| Rust | `example-rs/src/utils/` | Tests alongside their modules; run `cargo test --locked` |
| Go | `example-go/internal/demo/` | Tests alongside their packages; run `go test -race ./...` |

Run these commands from the corresponding language's example directory. Python
example tests are also collected by the SDK's pytest configuration. Credentialed
integration tests are described in the [live E2E guide](../e2e/README.md).

## Image provenance

The native and standalone Gateway Chat examples in every language require these
Gateway image builds:

| Image | GitHub repository | Build workflow |
| --- | --- | --- |
| `nearaidev/cloud-api` | `nearai/cloud-api` | `.github/workflows/build.yml` |
| `nearaidev/cvm-ingress` | `nearai/cvm-ingress` | `.github/workflows/build-push.yml` |
| `nearaidev/dstack-vpc` | `nearai/dstack-vpc` | `.github/workflows/build.yml` |
| `nearaidev/dstack-vpc-client` | `nearai/dstack-vpc-client` | `.github/workflows/build.yml` |

They also verify the following model image builds using authenticated
Compose Manager deployment-control evidence:

| Image | GitHub repository | Build workflow |
| --- | --- | --- |
| `nearaidev/vllm-proxy-rs` | `nearai/inference-proxy` | `.github/workflows/build.yml` |
| `nearaidev/compose-manager` | `nearai/compose-manager` | `.github/workflows/build.yml` |

Set `commit` pins in the example image policies to restrict accepted builds.
The policies check required Gateway images and container image builds recorded
by Compose Manager.

See the model image guides for [JavaScript](../js/docs/verification-guide.md#model-images-deployed-by-compose-manager),
[Python](../py/docs/verification-guide.md#model-images-deployed-by-compose-manager),
[Rust](../rs/docs/verification-guide.md), and [Go](../go/docs/verification-guide.md).
The standalone Gateway examples retain ciphertext separately from decrypted
output for receipt verification. Integrated clients capture those bytes internally.

## Direct endpoints

Direct examples use a model endpoint URL and a credential accepted by that endpoint.

Direct examples verify every returned model report and the response signature.
Integrated examples enable E2EE; bare examples use plaintext over HTTPS.
Direct clients are experimental. Requests use the verified model TLS fingerprints
by default.

Read `attestations` (`Attestations` in Go) for all reports matching the response signer.

See the [live E2E guide](../e2e/README.md) to run the integration tests with your
endpoint credentials and selected models.
