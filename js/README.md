# Verifiable AI SDK for TypeScript

Verify NEAR AI Cloud completion signatures and attestation evidence. The SDK
fetches and verifies evidence; your application sends the completion request and
retains its exact request and response bytes.

## What the SDK verifies

A successful verification establishes, for the selected flow:

- a signature covers the exact completion request and response bytes;
- the signature's signer matches fresh attested evidence;
- the Intel TDX quote, nonce, accepted TCB status, measured compose
  configuration, and runtime measurements are valid;
- supplied NVIDIA GPU evidence is verified for model attestations, or can be
  required by policy; and
- gateway evidence, when used, is bound to the TLS peer fingerprint
  independently observed by the client.

The SDK does not send inference requests, choose retry behavior, or turn model
evidence into a client-to-model TLS claim.

## Choose the claim you need

The completion signature's explicit `kind` selects exactly one verification
flow and its matching attestation. Do not infer the kind from the signed text
or mix the two flows.

### Verify a model response

Use a `provider_tee` signature with model attestation to verify that a
model-serving TEE signed the exact completion bytes. This is the normal
completion-verification flow. Keep the original bytes, use a canonical model ID
with `x-no-aliasing: true`, fetch a fresh nonce and matching model attestation,
then verify the response. A model attestation does not prove that the client
connected directly to the model CVM.

[Follow the model-response guide](./docs/verification-guide.md#verify-a-model-response).

### Verify a gateway response

Use a `gateway` signature with gateway attestation when you need to bind gateway
evidence to the TLS peer that served the completion. The application must
independently obtain that peer's SHA-256 SPKI fingerprint. This verifies a
gateway claim, not that a model-serving TEE produced the response. Standard
browser `fetch` and most Node `fetch` APIs do not expose the required peer
certificate data.

[Follow the gateway-response guide](./docs/verification-guide.md#verify-a-gateway-response).

## Requirements common to both flows

- Preserve the exact request and response bytes; do not parse and serialize
  them before response verification.
- Generate a fresh nonce for each evidence request.
- Use the signature's explicit kind and matching attestation and response
  verifier.
- Keep the SDK's verified attestation result in memory and pass that exact
  object to response verification. Re-verify raw evidence after serialization
  or a process boundary.
- Supply a deployment verifier when the application must restrict acceptable
  measured deployments.

## Documentation

- [Verification guide](./docs/verification-guide.md) for complete model and
  gateway workflows, policy configuration, and error handling.
- [API reference](./docs/api-reference.md) for exported APIs, types, fields,
  and structured error codes.

## Runtime

The package publishes ESM and is developed with Node.js 24. Browser consumers
can bundle it, though the default Intel verifier may require `crypto`,
`buffer`, and `stream` polyfills. Supply a custom quote verifier when your
runtime or trust model requires one.
