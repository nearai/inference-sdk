# Verifiable AI SDK for TypeScript

Verify NEAR AI Cloud completion signatures and attestation evidence. The SDK
fetches and verifies evidence; your application sends completion requests and
retains their exact request and response bytes when it verifies a response.

## What the SDK verifies

A successful attestation establishes:

- the Intel TDX quote, nonce, accepted TCB status, measured compose
  configuration, and runtime measurements are valid;
- supplied NVIDIA GPU evidence is accepted by the configured verifier for
  model attestations, or can be required by policy; and
- gateway evidence is bound to a TLS peer fingerprint independently observed
  by the client.

When verifying a response, the SDK additionally establishes that a signature
covers the exact request and response bytes and its signer is bound to the
matching verified evidence.

The default NVIDIA verifier sends GPU evidence to NVIDIA NRAS over HTTPS and
accepts its documented boolean overall result. It does not locally validate the
returned JWT/EAT signature. Supply `verifiers.nvidia` when your trust model
requires local JWT/EAT validation, different trust roots, or another
verification service.

The SDK does not send inference requests, choose retry behavior, or turn model
evidence into a client-to-model TLS claim.

## Choose the claim you need

The completion signature's explicit `kind` selects the matching response
verification flow. Do not infer a signature kind from signed text or mix model
and gateway evidence.

### Verify a model response

Use a `provider_tee` signature with model attestation to verify that a
model-serving TEE signed the exact completion bytes. This is the normal
completion-verification flow. Keep the original bytes, use a canonical model ID
with `x-no-aliasing: true`, fetch matching model attestation evidence, then
verify the response. The model-attestation fetch returns the fresh nonce used
for that evidence request. A model attestation does not prove that the client
connected directly to the model CVM.

[Follow the model-response guide](./docs/verification-guide.md#verify-a-model-response).

### Verify a gateway attestation

Fetch fresh gateway evidence and verify it against the SHA-256 SPKI fingerprint
independently observed for the attestation request's TLS peer. This verifies a
Cloud API gateway endpoint; it does not establish model execution. Standard
browser `fetch` and most Node `fetch` APIs do not expose the required peer
certificate data.

[Follow the gateway-attestation guide](./docs/verification-guide.md#verify-a-gateway-attestation).

### Verify a gateway response

Use a `gateway` signature with verified gateway evidence to verify the exact
completion bytes and gateway-service provenance. This is the matching response
verification flow when the signature kind is `gateway`; it does not establish
model execution.

## Requirements

- Use the nonce returned with each attestation fetch result when verifying that
  result. The SDK generates a fresh nonce for every evidence request.
- For response verification, preserve exact request and response bytes; use
  the signature's explicit kind with its matching evidence and response
  verifier.
- For gateway attestation, independently observe the TLS peer fingerprint of
  the attestation request.
- Verify raw evidence before using its result for response verification. Decide
  where to verify it again after storage or transfer.
- Supply a deployment verifier when the application must restrict acceptable
  measured deployments.

## Documentation

- [Verification guide](./docs/verification-guide.md) for complete model and
  gateway workflows, policy configuration, and error handling.
- [API reference](./docs/api-reference.md) for client and verification APIs,
  types, and fields.

## Runtime

The package publishes ESM and is developed with Node.js 24. Browser consumers
can bundle it, though the default Intel verifier may require `crypto`,
`buffer`, and `stream` polyfills. Supply a custom quote verifier when your
runtime or trust model requires one.
