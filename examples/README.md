# NEAR AI Inference SDK examples

These projects verify deployment evidence before sending Chat Completions,
then verify the response signature. All examples use
`z-ai/glm-5.3-flash` and read the API key from `NEARAI_API_KEY`.

```sh
export NEARAI_API_KEY=sk-your-api-key
```

## JavaScript (Node.js)

The examples use `@nearai/inference-sdk`, linked to the local TypeScript SDK.

Gateway and direct examples are grouped in separate folders and share the same
project configuration. Each entry point includes non-streaming and streaming calls:

| File | Usage | E2EE |
| --- | --- | --- |
| `gateway/bare.ts` | Verifies attestations and Gateway image provenance, uses `prepareE2eeChatRequest` for JSON/SSE, and verifies ciphertext signatures. | Enabled |
| `gateway/client.ts` | Configures Gateway image provenance, then uses `InferenceClient.chat.completions.create()` and `verifyResponse(id)`. | Enabled |
| `gateway/client-openai-sdk.ts` | Passes `inferenceClient.fetch` to one reusable OpenAI client, then calls `inferenceClient.verifyResponse(id)`. | Enabled |
| `direct/client.ts` | Experimental: connects using `DirectInferenceClient`, verifies every returned model attestation, then verifies responses by ID. | Enabled |
| `direct/client-openai-sdk.ts` | Experimental: passes `directClient.fetch` to the official OpenAI SDK, then verifies responses by ID. | Enabled |
| `direct/bare.ts` | Experimental: fetches and verifies direct model attestations and verifies exact response bytes. | Not implemented |

The examples in `gateway/` verify the Gateway's TLS identity.
The Gateway inference clients also pin later
evidence, Chat, and signature requests to that identity. They cache attestation
results for 60 minutes and retain response records for 60 minutes after body
completion. Change `SIGNING_ALGO` from `'ed25519'` to `'ecdsa'` to use ECDSA.

The Gateway bare example preserves the exact encrypted request and response bytes
before decryption for signature verification. The public E2EE helper creates
request-specific keys and protocol headers, including `x-no-aliasing: true`.
The example sets `Accept-Encoding: identity` and displays decrypted JSON or
SSE. The inference clients handle encryption, decryption, and byte capture
internally.

To use OHTTP, add `ohttp: true` to either inference client's constructor and
keep `SIGNING_ALGO` set to `'ed25519'`. JSON, streaming, and response-verification
calls stay the same. The endpoint must provide signed OHTTP configuration and
serve `/ohttp`. E2EE remains enabled independently.

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

### Direct model endpoints

> **Experimental — not recommended for production.** These examples use
> `DirectInferenceClient` or `DirectAttestationClient`, which are experimental
> in both browser and Node entry points. Use the Gateway examples and
> `InferenceClient` or `AttestationClient` for production. See the
> [known endpoint limitations](../js/docs/verification-guide.md#use-a-direct-model-endpoint).

`direct/client.ts`, `direct/client-openai-sdk.ts`, and `direct/bare.ts` use
`https://glm-5-3-flash.completions.near.ai/v1`, without Gateway attestation.
Set `NEARAI_API_KEY` to a credential accepted by that endpoint; a Gateway key is
not necessarily valid for direct inference.

```sh
pnpm --dir examples/example-js start:direct-client
pnpm --dir examples/example-js start:direct-client-openai-sdk
pnpm --dir examples/example-js start:direct-bare
```

All three verify every returned model attestation; the endpoint may omit other
serving instances. Direct TLS fingerprint
binding is currently disabled; standard HTTPS certificate validation still applies.
`DirectInferenceClient` selects a model key for routing and E2EE and requires response
signatures from the same signer. The bare example sends plaintext over HTTPS
and selects matching attestations when verifying the response signature.

### Image provenance

[`gateway/client.ts`](example-js/gateway/client.ts) and
[`gateway/bare.ts`](example-js/gateway/bare.ts) verify
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

These examples verify build provenance, not reproducible builds. They do not
verify Compose Manager runtime state, GLM runtime-image, or model-weight
provenance.

## Python

Uses `nearai-inference-sdk`, imported as `nearai_inference_sdk`.

Gateway and direct Chat entry points include non-streaming and streaming calls:

| File | Usage |
| --- | --- |
| `gateway/bare.py` | Verifies attestations and Gateway image provenance, prepares E2EE requests, and verifies encrypted response bytes. |
| `gateway/client.py` | Configures Gateway image provenance and uses `InferenceClient.chat.completions.create()` and `verify_response(id)`. |
| `gateway/client_openai_sdk.py` | Shares `inference_client.http_client` with one reusable `openai.AsyncOpenAI` client. |
| `direct/client.py` | Experimental direct client with E2EE and explicit response verification. |
| `direct/client_openai_sdk.py` | Experimental direct transport shared with `AsyncOpenAI`. |
| `direct/bare.py` | Experimental standalone report-set and response verification; sends plaintext over HTTPS. |

Gateway Chat examples explicitly enable E2EE; the Gateway SDK defaults to
`e2ee=False`. Gateway TLS verification is enabled by default. Change `SIGNING_ALGO` from
`'ed25519'` to `'ecdsa'` to use ECDSA throughout the workflow. The integrated
client caches attestations for 60 minutes per model and retains response records for
60 minutes after body completion. Both Gateway `bare.py` and `client.py` use the four
Gateway image policies listed above; they do not check model runtime images.

```sh
cd examples/example-py
uv run python gateway/client.py
uv run python gateway/bare.py
uv run python gateway/client_openai_sdk.py
uv run python direct/client.py
uv run python direct/client_openai_sdk.py
uv run python direct/bare.py
```

Requires Python 3.12 or later and [uv](https://docs.astral.sh/uv/).

Direct examples share the JavaScript clients' experimental limitations above.
For OHTTP, add `ohttp=True` to either inference client and retain Ed25519.

## Rust

Uses the `nearai-inference-sdk` crate, imported as `nearai_inference_sdk`.

```sh
cd examples/example-rs
# Manual attestation/signature workflow:
cargo run
# Integrated Gateway verification, E2EE, and response verification:
cargo run --bin client
```

The Python and Rust projects use the sibling SDK source through local path
dependencies. Replace those dependencies with released package versions when
using these examples outside this repository.
