# Verifiable AI SDK for TypeScript

This package verifies NEAR AI Cloud API attestation evidence and completion
signatures. It supports two deliberately separate claims:

- Model response verification binds a `provider_tee` signature over exact
  completion bytes to verified NEAR model evidence.
- Gateway verification binds gateway evidence to a TLS peer observed by the
  caller on the same connection. It does not establish model execution.

## Start here

Read the [TypeScript verification guide](./docs/verification-guide.md) for:

- a complete model-response verification flow that preserves raw bytes;
- report-data bindings, TCB policy, GPU evidence, and deployment provenance;
- custom quote, GPU, and provenance verifier contracts;
- signature lookup states and structured error handling; and
- same-connection gateway TLS verification requirements.

## SDK responsibilities

`NearAiCloudClient` fetches attestation evidence and response signatures. It
does not send completion requests or retain their bytes. Your completion client
must preserve the exact request and response bytes; do not parse and reserialize
JSON or SSE data before signature verification.

The public entry points are:

- `NearAiCloudClient.fetchNearModelAttestation` for NEAR model evidence;
- `verifyNearModelAttestation` for quote, nonce, measurement, and policy
  verification;
- `verifyProviderTeeResponse` for a model-serving signature over exact bytes;
- `verifyGatewayAttestation` and `verifyGatewayResponse` for the distinct
  gateway path; and
- `VerificationError` and `isVerificationError` for structured failure
  handling.

## Trust boundaries

The SDK verifies quote and measurement consistency, but does not embed an
allowlist for expected NEAR deployments. Supply a `ProvenanceVerifier` and set
`requireDeploymentProvenance: true` when a successful result must include your
deployment policy.

Model report fingerprints are server declarations, not client-observed model
TLS peers. Conversely, gateway verification requires a SHA-256 SPKI fingerprint
from a TLS connection controlled by the caller. Do not copy
`attestation.tls_cert_fingerprint` into `peerTlsCertFingerprint`.

## Runtime requirements

The package targets Node.js 22.13 or later. The default quote verifier uses
Intel DCAP verification. If model evidence includes GPU evidence, the default
GPU verifier contacts NVIDIA NRAS. Use custom verifiers when your deployment
needs different trust roots or network behavior.

The package ships its detailed guide in `docs/` alongside the built output.
