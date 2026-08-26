# Verifiable AI SDK for TypeScript

Verify NEAR AI Cloud completion signatures and attestation evidence in a
TypeScript application.

The main flow is deliberately small:

```ts
const signature = await client.fetchCompletionSignature({ completionId });
const nonce = generateNonce();
const attestation = await client.fetchModelAttestation({
  model,
  nonce,
  signature,
});
const verifiedAttestation = await verifyModelAttestation({
  attestation,
  nonce,
});
verifyModelResponse({
  requestBody,
  responseBody,
  signature,
  attestation: verifiedAttestation,
});
```

This proves that a model-serving TEE signed the exact request and response
bytes, and that its signing identity is bound to fresh, verified model evidence.
Your application must preserve the original bytes; do not parse and serialize
the request or response again before calling `verifyModelResponse`.
Keep the exact `verifiedAttestation` object in memory and pass it directly to
`verifyModelResponse`; re-verify raw evidence after a process or serialization
boundary.

Read the [TypeScript verification guide](./docs/verification-guide.md) for the
standard flow and the [API reference](./docs/api-reference.md) for every public
function, parameter, result type, and error type.

## Public API

The [API reference](./docs/api-reference.md) is the complete contract. It
includes all public functions, parameters, return values, callback types,
constants, and structured errors.

`NearAiCloudClient` does not send completion requests or retain their bytes.
Send completion requests with `NO_ALIASING_HEADER` set to `true` and use a
canonical model ID. `new NearAiCloudClient({ apiKey })` uses the production
endpoint, `https://cloud-api.near.ai/v1`; set `baseUrl` only for another Cloud
API environment.

## Gateway verification

Gateway verification is an optional complement to model-response verification.
It verifies that gateway evidence matches the SHA-256 SPKI fingerprint your
application observed for the TLS peer that served the completion. Standard
browser `fetch` and most Node `fetch` clients do not expose that fingerprint,
so this flow normally uses a TLS-aware backend transport. See the guide before
using this path.

## Runtime

The package publishes ESM and is developed with Node.js 24. Browser consumers
can bundle it, though the default Intel verifier may require `crypto`,
`buffer`, and `stream` polyfills. Supply a custom quote verifier when your
runtime or trust model requires one.
