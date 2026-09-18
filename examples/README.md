# NEAR AI Inference SDK examples

These projects verify Gateway and model attestations before sending Chat
Completions, then verify the response signature. All examples use
`z-ai/glm-5.3-flash` and read the API key from `NEARAI_API_KEY`.

```sh
export NEARAI_API_KEY=sk-your-api-key
```

## JavaScript (Node.js)

The examples use `@nearai/inference-sdk`, linked to the local TypeScript SDK.

The three entry points include non-streaming and streaming calls:

| File | Usage | E2EE |
| --- | --- | --- |
| `bare.ts` | Verifies attestations and Gateway image provenance, uses `prepareE2eeChatRequest` for JSON/SSE, and verifies ciphertext signatures. | Enabled |
| `client.ts` | Configures Gateway image provenance, then uses `InferenceClient.chat.completions.create()` and `verifyResponse(id)`. | Enabled |
| `client-openai-sdk.ts` | Passes `inferenceClient.fetch` to one reusable OpenAI client, then calls `inferenceClient.verifyResponse(id)`. | Enabled |

All three verify Gateway TLS identity. The inference clients also pin later
evidence, Chat, and signature requests to that identity. They cache attestation
results for 60 minutes and retain response records for 60 minutes after body
completion. Change `SIGNING_ALGO` from `'ed25519'` to `'ecdsa'` to use ECDSA.

The bare example preserves the exact encrypted request and response bytes
before decryption for signature verification. The public E2EE helper creates
request-specific keys and protocol headers, including `x-no-aliasing: true`.
The example sets `Accept-Encoding: identity` and displays decrypted JSON or
SSE. The inference clients handle encryption, decryption, and byte capture
internally.

The SDK must be built first because the example imports the local package's
published `dist` files.

```sh
pnpm --dir js install --frozen-lockfile
pnpm --dir js build
pnpm --dir examples/example-js install --frozen-lockfile
pnpm --dir examples/example-js check
pnpm --dir examples/example-js start:client
pnpm --dir examples/example-js start:bare
pnpm --dir examples/example-js start:client-openai-sdk
```

Requires Node.js 24 or later.

### Image provenance

[`client.ts`](example-js/client.ts) and [`bare.ts`](example-js/bare.ts) verify
the build provenance of these four required Gateway images:

| Image | GitHub repository | Build workflow |
| --- | --- | --- |
| `nearaidev/cloud-api` | `nearai/cloud-api` | `.github/workflows/build.yml` |
| `nearaidev/cvm-ingress` | `nearai/cvm-ingress` | `.github/workflows/build-push.yml` |
| `nearaidev/dstack-vpc` | `nearai/dstack-vpc` | `.github/workflows/build.yml` |
| `nearaidev/dstack-vpc-client` | `nearai/dstack-vpc-client` | `.github/workflows/build.yml` |

Both examples call `verifyDeploymentImageProvenance` with the authenticated
`appCompose` and image policies in a deployment verifier. `client.ts` configures
`gatewayVerification.verifiers.deployment`; `bare.ts` passes
`verifiers.deployment` to `verifyGatewayAttestation`. The SDK extracts the
digests and verifies GitHub Sigstore provenance.
Every listed image is required; other images are outside this check. References
must contain literal digests: `image:tag@sha256:...` is accepted, but tags alone
and unresolved `${VARIABLE:-default}` expressions are not.
The policies belong to these examples, not an SDK default allowlist. Add `commit`
to each policy to require a reviewed source commit.

Gateway/model attestation and image-check failures block both Chat modes.
`client.ts` reuses successful checks through its 60-minute attestation cache;
`bare.ts` verifies the deployments before sending either request. Run them with
the `start:client` and `start:bare` commands above.

These examples verify build provenance, not reproducible builds. Checking the
running Compose Manager and inference-proxy images requires direct Compose
Manager evidence, which this SDK does not retrieve. These examples do not check
GLM runtime-image or model-weight provenance.

## Python

Uses `nearai-inference-sdk`, imported as `nearai_inference_sdk`.

Each entry point includes non-streaming and streaming Chat with E2EE:

| File | Usage |
| --- | --- |
| `bare.py` | Verifies attestations and Gateway image provenance, prepares E2EE requests, and verifies encrypted response bytes. |
| `client.py` | Configures Gateway image provenance and uses `InferenceClient.chat.completions.create()` and `verify_response(id)`. |
| `client_openai_sdk.py` | Shares `inference_client.http_client` with one reusable `openai.AsyncOpenAI` client. |

Gateway TLS verification and E2EE are enabled. Change `SIGNING_ALGO` from
`'ed25519'` to `'ecdsa'` to use ECDSA throughout the workflow. The integrated
client caches attestations for 60 minutes and retains response records for
60 minutes after body completion. Both `bare.py` and `client.py` use the four
Gateway image policies listed above; they do not check model runtime images.

```sh
cd examples/example-py
uv run python client.py
uv run python bare.py
uv run python client_openai_sdk.py
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
