# NEAR AI Inference SDK for TypeScript

`@nearai/inference-sdk` verifies Gateway and model attestations in Node.js and
browsers, and provides encrypted Chat Completions for NEAR model deployments.

## Clients and verification

- `InferenceClient` verifies Gateway and model evidence before sending a chat
  request, encrypts supported fields, and decrypts the response. It provides
  `chat.completions.create()` and a reusable `fetch` for the official OpenAI SDK.
- `InferenceClient.verifyResponse(id)` verifies a completion's signature using
  its exact request and response bytes and the evidence retained for that request.
- `AttestationClient` fetches evidence and signatures. Standalone verification
  functions let applications control the verification flow.
- `DirectInferenceClient` connects to a model's own endpoint, verifies every
  returned model attestation, and provides the same Chat, E2EE, and response-verification
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

## Defaults

Both inference clients support streaming and non-streaming Chat Completions. E2EE is
enabled by default, with `signingAlgo: 'ed25519'`; `'ecdsa'` is also supported.
Setting `e2ee: false` disables encryption while retaining deployment verification.

Attestation results are cached for 60 minutes. Set
`attestationCacheTimeToLiveMs: 0` to verify before every request. Response
records have a separate 60-minute retention period, configured through
`responseCacheTimeToLiveMs`.

Import from `@nearai/inference-sdk/node` for Node.js with endpoint TLS verification
and subsequent request pinning. The direct client allows TLS keys from the
verified model attestations sharing its selected model signer; the Gateway client pins
the Gateway key.
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
