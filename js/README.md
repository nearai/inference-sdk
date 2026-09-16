# Verifiable AI SDK for TypeScript

`verifiable-ai-sdk` verifies Gateway and model attestations in Node.js and
browsers, and provides encrypted Chat Completions for NEAR model deployments.

## Clients and verification

- `SecureClient` verifies Gateway and model evidence before sending a chat
  request, encrypts supported fields, and decrypts the response. It provides
  `chat.completions.create()` and a reusable `fetch` for the official OpenAI SDK.
- `SecureClient.verifyResponse(id)` verifies a completion's signature using
  its exact request and response bytes and the evidence retained for that request.
- `AttestationClient` fetches evidence and signatures. Standalone verification
  functions let applications control the verification flow.
- `fetchImageProvenance` and `verifyImageProvenance` check GitHub image build
  proofs against caller-supplied repository, workflow, and optional version rules.

Gateway attestation verifies the Gateway's TEE and signing identity.
Model attestation verifies the model deployment's TEE, signing identity,
measurements, and available GPU evidence.

Response signatures bind specific request and response bytes to an attested
signer. A `provider_tee` signature identifies a model signer; a `gateway`
signature identifies a Gateway signer and does not establish model execution.

## Defaults

`SecureClient` supports streaming and non-streaming Chat Completions. E2EE is
enabled by default, with `signingAlgo: 'ed25519'`; `'ecdsa'` is also supported.
Setting `e2ee: false` disables encryption while retaining deployment verification.

Attestation results are cached for 15 minutes. Set
`attestationCacheTimeToLiveMs: 0` to verify before every request. Response
records have a separate 15-minute retention period, configured through
`responseCacheTimeToLiveMs`.

Import from `verifiable-ai-sdk/node` for Node.js with Gateway TLS verification
and subsequent request pinning. Use `verifiable-ai-sdk` in browsers, where
Fetch does not expose the TLS peer certificate. The package publishes ESM and
requires Node.js 24 or later for Node usage.

## Documentation

- [Verification guide](./docs/verification-guide.md): Chat, E2EE, proxies,
  deployment policies, and response verification.
- [API reference](./docs/api-reference.md): public functions, parameters,
  defaults, and result fields.
- [Runnable examples](../examples/README.md): bare verification, SecureClient,
  and OpenAI SDK integration.
