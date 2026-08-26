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

See the [TypeScript verification guide](./docs/verification-guide.md) for a
complete example, policy and verifier configuration, structured error handling,
and the separate gateway-verification flow.

## Public API

- `NearAiCloudClient` fetches completion signatures and attestation evidence.
- `fetchCompletionSignature`, `fetchModelAttestation`, `verifyModelAttestation`, and
  `verifyModelResponse` implement the standard model-response flow.
- `fetchGatewayAttestation`, `verifyGatewayAttestation`, and
  `verifyGatewayResponse` support the distinct gateway claim.
- `generateNonce` creates the fresh nonce used when requesting and verifying
  evidence.
- `VerificationError` and `isVerificationError` expose stable, structured
  failures.

`NearAiCloudClient` does not send completion requests or retain their bytes.
Send completion requests with `NO_ALIASING_HEADER` set to `true` and use a
canonical model ID. `new NearAiCloudClient({ apiKey })` uses the production
endpoint, `https://cloud-api.near.ai/v1`; set `baseUrl` only for another Cloud
API environment.

## Gateway verification

Gateway verification is not a substitute for model-response verification. It
binds gateway evidence to a SHA-256 SPKI fingerprint observed by your client on
the same TLS connection as the response. A normal browser or `fetch` client
cannot usually make that claim because it cannot expose the peer certificate or
prove connection reuse. See the guide before using this path.

## Runtime

The package publishes ESM and is developed with Node.js 24. Browser consumers
can bundle it, though the default Intel verifier may require `crypto`,
`buffer`, and `stream` polyfills. Supply a custom quote verifier when your
runtime or trust model requires one.
