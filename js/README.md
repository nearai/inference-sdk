# Verifiable AI SDK for TypeScript

Verify NEAR AI Cloud completion signatures and attestation evidence.
`AttestationClient` fetches signatures and evidence; standalone functions
verify them. Your application sends completion requests and retains their exact
request and response bytes when it verifies a response.

## What the SDK verifies

A successful attestation establishes:

- the Intel TDX quote, nonce, accepted TCB status, measured compose
  configuration, and runtime measurements are valid;
- supplied NVIDIA GPU evidence is accepted by the configured verifier for
  model attestations, or can be required by policy; and
- gateway evidence verifies the Gateway signer and, with the default TLS
  policy, matches the TLS peer observed by the client to the fingerprint bound
  into the verified quote.

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

The completion signature's explicit `kind` identifies the trust boundary that
signed the completion and selects its verification flow. A `provider_tee`
signature comes from the model-serving TEE; a `gateway` signature comes from
the NEAR AI Cloud Gateway for the client-visible response.

### Verify a model response

Use a `provider_tee` signature with model attestation to verify that a
model-serving TEE signed the exact completion bytes. This is the normal
completion-verification flow. Keep the original bytes, use a canonical model ID
with `x-no-aliasing: true`, fetch matching model attestation evidence, then
verify the response. The model-attestation fetch returns the client binding used
for that evidence request. A model attestation does not prove that the client
connected directly to the model CVM.

[Follow the model-response guide](./docs/verification-guide.md#verify-a-model-response).

### Verify a gateway attestation

Fetch fresh Gateway evidence to verify a Cloud API Gateway deployment. In
Node, the SDK captures the SHA-256 SPKI fingerprint of the TLS peer serving
that exact evidence request and checks it against the quote by default. Browser
runtimes cannot access the peer certificate, so they must pass
`policy: { verifyTlsBinding: false }` when fetching; that verifies the
signer-and-nonce quote layout without making a TLS claim. Gateway evidence does
not establish model execution.

[Follow the gateway-attestation guide](./docs/verification-guide.md#verify-a-gateway-attestation).

### Verify a gateway response

Use a `gateway` signature with verified gateway evidence to verify the exact
completion bytes and gateway-service provenance. This is the matching response
verification flow when the signature kind is `gateway`; it does not establish
model execution.

## Requirements

- Use the `clientBinding` returned with each attestation fetch result when
  verifying that result. The SDK generates a fresh nonce for every evidence
  request.
- For response verification, preserve exact request and response bytes; use
  the signature's explicit kind with its matching evidence and response
  verifier.
- For Gateway attestation, pass the fetch result's `attestation` and
  `clientBinding`, and `policy` directly to `verifyGatewayAttestation`. By
  default it requires a TLS peer fingerprint; Node captures it for the evidence
  request. Browser callers must pass `policy: { verifyTlsBinding: false }` to
  `client.fetchGatewayAttestation`.
- Verify raw evidence before using its result for response verification. Decide
  where to verify it again after storage or transfer.
- Supply a deployment verifier when the application must restrict acceptable
  measured deployments.

## Documentation

- [Verification guide](./docs/verification-guide.md) for complete model and
  gateway workflows, policy configuration, and error handling.
- [API reference](./docs/api-reference.md) for Cloud request and verification APIs,
  types, and fields.

## Runtime

The package publishes ESM and is developed with Node.js 24. In Node,
`AttestationClient.fetchGatewayAttestation` uses HTTPS to capture the TLS peer fingerprint for
the evidence request, satisfying the default Gateway policy. Browser consumers
can bundle the SDK, but browser fetch does not expose peer certificates. They
must use `verifyTlsBinding: false` when fetching Gateway evidence; that path
returns `tlsBinding.kind: 'none'` after signer-and-nonce quote verification.
`GatewayAttestation.spkiFingerprint` is Gateway-reported,
`GatewayClientBinding.spkiFingerprint` is client-observed, and a successful
`GatewayTlsBinding.spkiFingerprint` is their verified match.
The default Intel verifier may require `crypto`, `buffer`,
and `stream` polyfills in browsers. Supply a custom quote verifier when your
runtime or trust model requires one.
