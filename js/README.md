# Verifiable AI SDK for TypeScript

Verify NEAR AI Cloud deployment attestations and completion signatures.
`AttestationClient` retrieves Cloud API evidence and signatures; standalone
functions verify them. Your application sends completion requests and preserves
their exact request and response bytes.

## Verification flow

Use three stages for a verified completion:

1. Before sending the completion, fetch and verify both the Gateway deployment
   and the target model deployment.
2. Send a completion to the canonical model with `x-no-aliasing: true`, then
   retain its completion ID and exact request and response bytes.
3. Fetch the completion signature and verify those bytes with the preflight
   evidence selected by `signature.kind`.

The signature kind is a receipt-dispatch value, not a choice between two
workflows. Both deployments are checked before the request. It selects the
evidence that can verify the returned bytes:

| `signature.kind` | Response verifier | Successful result |
| --- | --- | --- |
| `provider_tee` | `verifyModelResponse` with the verified model attestation | The model-serving TEE signer bound to that attestation signed the exact request and response bytes. |
| `gateway` | `verifyGatewayResponse` with the verified Gateway attestation | The Gateway signer bound to that attestation signed the exact client-visible request and response bytes. |

If the relevant signing identity does not match the preflight result, response
verification fails. Do not substitute unverified evidence for a failed match.

## What attestations establish

A successful model attestation verifies its quote, nonce, accepted TCB status,
measured deployment, runtime measurements, model signer, and configured GPU
evidence policy. A successful Gateway attestation verifies the equivalent
Gateway deployment evidence and signer. The `/node` client also verifies the
TLS peer observed while fetching Gateway evidence by default.

The default NVIDIA verifier sends supplied GPU evidence to NVIDIA NRAS over
HTTPS and accepts its documented boolean overall result. It does not locally
validate the returned JWT/EAT signature. Supply `verifiers.nvidia` when your
trust model requires local JWT/EAT validation, different trust roots, or
another verification service.

## Evidence boundary

The two preflight attestations and one completion signature do not yet form a
complete model-to-Gateway-to-final-response chain. In particular, a `gateway`
signature proves the final client-visible bytes were signed by the verified
Gateway, but does not cryptographically bind them to an upstream response from
the verified model. A `provider_tee` signature verifies the model-signed bytes,
but does not bind that signature to the preflight Gateway evidence.

This limitation matters when Cloud API rewrites a provider response before
returning it. The planned paired provider signature and Gateway receipt are
tracked in [cloud-api#986](https://github.com/nearai/cloud-api/issues/986).

## Requirements

- Use the `clientBinding` returned with each attestation fetch result when
  verifying that result. The SDK generates a fresh nonce for every evidence
  request.
- Verify Gateway and model evidence before sending the completion. Keep the
  resulting verified values for the receipt-verification stage.
- Preserve exact completion request and response bytes. Do not parse and
  serialize them again before response verification.
- Use the signature's explicit `kind` only to choose the matching response
  verifier and preflight result.
- Supply a deployment verifier when your application must restrict acceptable
  measured deployments.

The SDK does not send inference requests, choose retry behavior, or turn model
evidence into a client-to-model TLS claim.

## Documentation

- [Verification guide](./docs/verification-guide.md) explains the complete
  three-stage flow, policies, and error handling.
- [API reference](./docs/api-reference.md) documents Cloud request and
  verification APIs, types, and fields.

## Runtime

The package publishes ESM and is developed with Node.js 24. Import from
`verifiable-ai-sdk/node` for the Node client, whose Gateway fetch defaults to
TLS binding. Import from `verifiable-ai-sdk` for the generic client, whose
Gateway fetch defaults to the no-TLS layout and returns `tlsBinding.kind:`
`'none'`. `GatewayAttestation.spkiFingerprint` is Gateway-reported,
`GatewayClientBinding.spkiFingerprint` is client-observed, and a successful
`GatewayTlsBinding.spkiFingerprint` is their verified match.

The default Intel verifier may require `crypto`, `buffer`, and `stream`
polyfills in browsers. Supply a custom quote verifier when your runtime or
trust model requires one.
