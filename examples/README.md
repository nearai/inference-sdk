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

Choose a model available in the selected endpoint's catalog. Chat client examples
and the standalone Gateway Chat examples explicitly enable field-level E2EE;
use a NEAR TEE model for those examples. Responses, Messages, and System One keep
E2EE disabled. OHTTP is independent of E2EE and requires signed key configuration
and an `/ohttp` endpoint. System One uses neither E2EE nor OHTTP.

Runnable examples make one explicit receipt-verification call and propagate failure.
Native clients and official SDK adapters disable automatic inference retries.

Bare Gateway Chat examples verify the response with the model key selected for the
request, then show how many verified reports share the response signer.

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

A dash means the vendor has no official SDK for that language. Official SDK
examples share the inference client's verified transport and verify receipts
through that same owner. OpenAI uses the `/v1/` base URL; Anthropic and TypeSafe examples
derive their API root from it. System One examples disable compression and inference
retries, and use `X-Generation-Id` as the receipt ID. Native and official examples ask
the same billing, team, and urgency questions by default and print answers after
verification.

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

Use `pnpm start:<entry-name>` for Gateway examples, such as
`pnpm start:chat-completions-with-openai-sdk`, and `start:direct-<entry-name>`
for direct examples. Existing `start:client`, `start:bare`,
`start:client-openai-sdk`, and existing direct aliases remain available.

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

`cargo run` and `cargo run --bin client` remain aliases for Gateway standalone
and integrated Chat. The Rust client exposes its reqwest transport directly.

### Go setup

Requires Go 1.26.10+. The SDK embeds the DCAP verifier. The example module
replaces the SDK dependency with the sibling source.

```sh
cd examples/example-go
go run ./gateway/chat-completions-with-openai-sdk
```

`go run .` remains an alias for the official OpenAI Gateway example. See the
[Go example guide](example-go/README.md). Replace local path/link dependencies
with released package versions when copying examples out of this repository.

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

## Direct endpoints

Direct clients are experimental. Set `NEARAI_BASE_URL` and `NEARAI_API_KEY` for the model endpoint.

Direct examples verify every returned model report and use standard HTTPS without
attested TLS pinning. Integrated
clients use E2EE and require response signatures from the selected model signer.
Standalone direct examples send plaintext over HTTPS and verify exact response
bytes against the matching attestation group.

See the [live E2E guide](../e2e/README.md) to run the integration tests with your
endpoint credentials and selected models.
