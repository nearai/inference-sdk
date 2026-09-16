# NEAR AI Inference SDK examples

These projects verify Gateway and model attestations before sending Chat
Completions, then verify the response signature. All examples use
`z-ai/glm-5.3-flash` and read the API key from `NEARAI_API_KEY`.

```sh
export NEARAI_API_KEY=sk-your-api-key
```

## JavaScript (Node.js)

The examples use `@nearai/inference-sdk`, linked to the local TypeScript SDK.

The three basic entry points include non-streaming and streaming calls:

| File | Usage | E2EE |
| --- | --- | --- |
| `bare.ts` | Fetches and verifies evidence, sends requests, and verifies signatures using standalone functions. | Not included |
| `client.ts` | Uses `InferenceClient.chat.completions.create()` and `verifyResponse(id)`. | Enabled |
| `openai-sdk-compatible.ts` | Passes `inferenceClient.fetch` to one reusable OpenAI client, then calls `inferenceClient.verifyResponse(id)`. | Enabled |

All three verify Gateway TLS identity. The inference clients also pin later
evidence, Chat, and signature requests to that identity. They cache attestation
results for 60 minutes and retain response records for 60 minutes after body
completion. Change `SIGNING_ALGO` from `'ed25519'` to `'ecdsa'` to use ECDSA.

The bare example preserves exact request and response bytes for signature
verification. It sends `x-no-aliasing: true` and `Accept-Encoding: identity`.
The inference clients handle byte capture internally.

The SDK must be built first because the example imports the local package's
published `dist` files.

```sh
pnpm --dir js install --frozen-lockfile
pnpm --dir js build
pnpm --dir examples/example-js install --frozen-lockfile
pnpm --dir examples/example-js check
pnpm --dir examples/example-js start:client
pnpm --dir examples/example-js start:bare
pnpm --dir examples/example-js start:openai-sdk-compatible
```

Requires Node.js 24 or later.

### Image provenance

[`client-provenance.ts`](example-js/client-provenance.ts) verifies these four
required Gateway images:

| Image | GitHub repository | Build workflow |
| --- | --- | --- |
| `nearaidev/cloud-api` | `nearai/cloud-api` | `.github/workflows/build.yml` |
| `nearaidev/cvm-ingress` | `nearai/cvm-ingress` | `.github/workflows/build-push.yml` |
| `nearaidev/dstack-vpc` | `nearai/dstack-vpc` | `.github/workflows/build.yml` |
| `nearaidev/dstack-vpc-client` | `nearai/dstack-vpc-client` | `.github/workflows/build.yml` |

The `gatewayVerification.verifiers.deployment` callback calls
`verifyDeploymentImageProvenance` with the authenticated `appCompose` and the
image policies. The SDK extracts the digests and verifies GitHub Sigstore provenance.
Every listed image is required; other images are outside this check. References
must contain literal digests: `image:tag@sha256:...` is accepted, but tags alone
and unresolved `${VARIABLE:-default}` expressions are not.
The policies belong to this example, not an SDK default allowlist. Add `commit`
to each policy to require a reviewed source commit.

```sh
pnpm --dir examples/example-js start:client-provenance
```

Gateway/model attestation and image-check failures block Chat. Successful checks
reuse the client's 60-minute attestation cache. The example then sends a
non-streaming GLM-5.3 request and calls `verifyResponse(id)`.

The example verifies build provenance, not reproducible builds. Checking the
running Compose Manager and inference-proxy images requires direct Compose
Manager evidence, which this SDK does not retrieve. This example does not check
GLM runtime-image or model-weight provenance.

## Python

Uses `nearai-inference-sdk`, imported as `nearai_inference_sdk`.

```sh
cd examples/example-py
uv run python main.py
```

Requires Python 3.12 or later and [uv](https://docs.astral.sh/uv/).

## Rust

Uses the `nearai-inference-sdk` crate, imported as `nearai_inference_sdk`.

```sh
cd examples/example-rs
cargo run
```

The Python and Rust projects use the sibling SDK source through local path
dependencies. Replace those dependencies with released package versions when
using these examples outside this repository.
