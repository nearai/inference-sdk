# NEAR AI Inference SDK for TypeScript

`@nearai/inference-sdk` provides Chat Completions through an attested Gateway
in Node.js and browsers. It verifies model attestations when supported, with
optional client E2EE for NEAR model deployments.

> **Experimental:** `DirectInferenceClient` and `DirectAttestationClient` are
> not recommended for production in either the browser or Node entry point.
> Use the Gateway `InferenceClient` or `AttestationClient` for production.
> See the [known direct-endpoint limitations](./docs/verification-guide.md#use-a-direct-model-endpoint).

## Clients and verification

- `InferenceClient` verifies Gateway evidence and checks whether the requested
  model supports NEAR model attestation. Supported models also require verified
  model evidence; other models use the Incognito, Gateway-only flow. With `e2ee: true`,
  it encrypts supported fields to a NEAR model and decrypts the response. It
  provides `chat.completions.create()` and a reusable `fetch` for the official
  OpenAI SDK.
- `InferenceClient.verifyResponse(id)` verifies a completion's signature using
  its exact request and response bytes and the evidence retained for that request.
- `AttestationClient` fetches model metadata, evidence, and signatures.
  Standalone verification functions let applications control the flow.
- `DirectInferenceClient` connects to a model's own endpoint, verifies every
  returned attestation, and provides the same Chat, E2EE, and response-verification
  methods without Gateway verification. `DirectAttestationClient` fetches direct
  attestations and signatures for a manual flow.
- `prepareE2eeChatRequest({ request, modelKey })` encrypts a raw Chat request
  using a model public key and returns the request and a JSON/SSE response
  decryptor. Applications verify the model key, send the request, and verify its
  signature separately.
- `verifyDeploymentImageProvenance` checks required deployment images against
  caller-supplied GitHub build policies. Individual image fetch and verification
  helpers are also available.

Gateway attestation verifies the Gateway's TEE and signing identity.
Model attestation verifies the model deployment's TEE, signing identity,
measurements, and available GPU evidence.

Response signatures bind specific request and response bytes to an attested
signer. A `provider_tee` signature identifies a model signer; a `gateway`
signature identifies a Gateway signer and does not establish model execution.
Gateway verification alone does not establish that a model runs in a TEE.
Incognito means the SDK verifies the Gateway without verifying model evidence.

## Defaults

Both inference clients support streaming and non-streaming Chat Completions.
`InferenceClient` defaults to `e2ee: false`; set `e2ee: true` to enable field
encryption for a supported model. `DirectInferenceClient` keeps E2EE enabled
by default. Both default to `signingAlgo: 'ed25519'`; `'ecdsa'` is also supported.

With E2EE disabled, attested models still require all returned model reports
to pass and use a verified model routing key. Incognito models skip model
evidence and key routing; `verifyResponse(id)` accepts only a Gateway signature.
E2EE and configured model deployment policies require model attestation and
reject Incognito models before Chat.

Set `ohttp: true` on either inference client to encrypt the Chat HTTP request
and response to the attested endpoint. OHTTP requires Ed25519 and is disabled
by default. OHTTP and field-level E2EE are independent. Gateway OHTTP also works
with Incognito models, protecting the exchange to the Gateway.

Attestation results and model verification decisions are cached for
60 minutes. Set `attestationCacheTimeToLiveMs: 0` to check every request. Response
records have a separate 60-minute retention period, configured through
`responseCacheTimeToLiveMs`.

Import from `@nearai/inference-sdk/node` for Node.js with Gateway TLS verification
and subsequent request pinning. Direct TLS fingerprint binding is currently
disabled in both entry points; standard HTTPS certificate validation still applies.
Use `@nearai/inference-sdk` in browsers, where
Fetch does not expose the TLS peer certificate. The package publishes ESM and
requires Node.js 24 or later for Node usage.

## Documentation

- [Verification guide](./docs/verification-guide.md): Chat, E2EE, proxies,
  deployment policies, and response verification.
- [API reference](./docs/api-reference.md): public functions, parameters,
  defaults, and result fields.
- [Runnable examples](../examples/README.md): Gateway and direct-model clients,
  standalone verification, and OpenAI SDK integration.
