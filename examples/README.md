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
| `NEARAI_MODEL` | Chat/Responses: `z-ai/glm-5.3-flash`; required for System One |
| `NEARAI_SIGNING_ALGO` | `ed25519` (default) or `ecdsa`, used for evidence and receipts, and for Chat E2EE |
| `NEARAI_OHTTP` | `true` enables OHTTP for integrated Chat and Responses clients; requires Ed25519 |
| `NEARAI_EXPECT_SIGNATURE_KIND` | System One: `gateway` (default) or `provider_tee`; the latter requires verified model evidence |

Choose a model available in the selected endpoint's catalog. Chat client examples
and the standalone Gateway Chat examples explicitly enable field-level E2EE;
use a NEAR TEE model for those examples. Responses and System One keep
E2EE disabled. OHTTP is independent of E2EE and requires signed key configuration
and an `/ohttp` endpoint. System One uses neither E2EE nor OHTTP.

Runnable examples make one explicit receipt-verification call and propagate failure.
Native clients and official SDK adapters disable automatic inference retries.

## Entry points

Each Chat or Responses entry point runs JSON and SSE. Commands below
run from `examples/example-js`, `examples/example-py`, `examples/example-rs`, or
`examples/example-go`, respectively.

| Capability | JavaScript | Python | Rust | Go |
| --- | --- | --- | --- | --- |
| Gateway Chat, native client | `node gateway/client.ts` | `uv run python gateway/client.py` | `cargo run --bin gateway-client` | `go run ./gateway/client` |
| Gateway Chat, standalone verification | `node gateway/bare.ts` | `uv run python gateway/bare.py` | `cargo run --bin gateway-bare` | `go run ./gateway/bare` |
| Gateway Chat, official OpenAI SDK | `node gateway/client-openai-sdk.ts` | `uv run python gateway/client_openai_sdk.py` | — | `go run ./gateway/openai` |
| Responses, native client | `node gateway/responses.ts` | `uv run python gateway/responses.py` | `cargo run --bin responses` | `go run ./gateway/responses-client` |
| Responses, official OpenAI SDK | `node gateway/responses-openai-sdk.ts` | `uv run python gateway/responses_openai_sdk.py` | — | `go run ./gateway/responses` |
| System One, native client | `node gateway/jev.ts` | `uv run python gateway/jev.py` | `cargo run --bin systemone` | `go run ./gateway/systemone` |
| System One, official Jev SDK | `node gateway/jev-sdk.ts` | `uv run python gateway/jev_sdk.py` | — | — |
| Direct Chat, native client | `node direct/client.ts` | `uv run python direct/client.py` | `cargo run --bin direct-client` | `go run ./direct/client` |
| Direct Chat, standalone verification | `node direct/bare.ts` | `uv run python direct/bare.py` | `cargo run --bin direct-bare` | `go run ./direct/bare` |
| Direct Chat, official OpenAI SDK | `node direct/client-openai-sdk.ts` | `uv run python direct/client_openai_sdk.py` | — | `go run ./direct/openai` |

A dash means the vendor has no official SDK for that language. Official SDK
examples share the inference client's verified transport and verify receipts
through that same owner. OpenAI uses the `/v1/` base URL; Jev examples
derive their API root from it. Jev disables compression and inference retries,
and uses `X-Generation-Id` as the receipt ID. Its native and official examples ask
the same billing, team, and urgency questions and print answers after verification.

### JavaScript setup

Requires Node.js 24.22.1+. Build the local SDK before running examples:

```sh
pnpm --dir js install --frozen-lockfile
pnpm --dir js build
pnpm --dir examples/example-js install --frozen-lockfile
cd examples/example-js
node gateway/client.ts
```

Existing `pnpm start:client`, `start:bare`, `start:client-openai-sdk`, `start:jev`,
`start:jev-sdk`, and `start:direct-*` commands remain available.

### Python setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). The example project
imports the sibling Python SDK through an editable path dependency.

```sh
cd examples/example-py
uv sync --locked
uv run python gateway/client.py
```

### Rust setup

The examples use the sibling Rust SDK through a path dependency. See the
[Rust build requirements](../rs/README.md).

```sh
cd examples/example-rs
cargo run --locked --bin gateway-client
```

`cargo run` and `cargo run --bin client` remain aliases for Gateway standalone
and integrated Chat. The Rust client exposes its reqwest transport directly.

### Go setup

Requires Go 1.26.10+. The SDK embeds the DCAP verifier. The example module
replaces the SDK dependency with the sibling source.

```sh
cd examples/example-go
go run ./gateway/openai
```

`go run .` remains an alias for the official OpenAI Gateway example. See the
[Go example guide](example-go/README.md). Replace local path/link dependencies
with released package versions when copying examples out of this repository.

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

These are example admission policies. Add reviewed commit pins for stricter
policy. Gateway references must contain literal digests; `image:tag@sha256:...`
is accepted, while tags alone and unresolved variables are not. Each listed
image is required. Model checks authenticate recorded deployment intent; they
do not establish which containers or weights are currently running.

See the model image guides for [JavaScript](../js/docs/verification-guide.md#model-images-deployed-by-compose-manager),
[Python](../py/docs/verification-guide.md#model-images-deployed-by-compose-manager),
[Rust](../rs/docs/verification-guide.md), and [Go](../go/docs/verification-guide.md).
The standalone Gateway examples retain ciphertext separately from decrypted
output for receipt verification. Integrated clients capture those bytes internally.

## Direct endpoints

Direct clients are experimental. Use Gateway clients for production and an
endpoint-accepted credential for direct inference.

All direct examples verify every returned model attestation; an endpoint may
omit other serving instances. Standard HTTPS certificate validation applies,
while direct TLS fingerprint binding to attestation remains disabled. Integrated
clients use E2EE and require response signatures from the selected model signer.
Standalone direct examples send plaintext over HTTPS and verify exact response
bytes against the matching attestation group.

See the [live E2E guide](../e2e/README.md) to run the integration tests with your
endpoint credentials and selected models.

## Browser (Private TEE chat)

[`example-browser`](example-browser/README.md) provides a chat UI with encrypted
streaming, deployment evidence, and verified response receipts. Its README
covers local setup and browser deployment requirements.
