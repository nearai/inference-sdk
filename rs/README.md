# verifiable-ai-sdk (Rust)

`verifiable-ai-sdk` verifies NEAR AI Cloud deployment attestations and the
completion signatures returned by Cloud API. It separates evidence retrieval,
deployment verification, and verification of an exact completion's request and
response bytes.

## Documentation

- [Verification guide](./docs/verification-guide.md) explains which evidence
  and response-verification path to use for `provider_tee` and `gateway`
  signatures.
- [API reference](./docs/api-reference.md) lists the Cloud API client,
  functions, return values, policies, and callback traits.

## Install

```toml
[dependencies]
verifiable-ai-sdk = "0.1"
```

The guide includes complete model and Gateway verification flows. In both
cases, retain the exact bytes sent to and received from the completion endpoint:
the SDK verifies those bytes without reserializing them.

There are two attestation classes. Model evidence verifies a model-serving TEE
deployment; Gateway evidence verifies the Cloud API Gateway deployment. A
completion signature binds exact request and response bytes to one of those
verified signers. Its `CompletionSignatureKind` selects which path applies:
`ProviderTee` establishes model-issued bytes, while `Gateway` establishes
Gateway-issued client-visible bytes and does not establish model execution.

Gateway TLS binding is enabled by default. The Rust client requests the
Gateway TLS fingerprint, captures the peer certificate for that same HTTPS
request, and returns the resolved policy with the evidence. Runtimes without
peer-certificate access must use
`GatewayAttestationPolicy { verify_tls_binding: false, ..Default::default() }`
when calling `AttestationClient::fetch_gateway_attestation`. The request then
uses the signer-and-nonce quote layout instead and verification returns
`GatewayTlsBinding::None`; it makes no TLS claim.
`GatewayAttestation::spki_fingerprint` is Gateway-reported,
`GatewayClientBinding::spki_fingerprint` is client-observed, and
`GatewayTlsBinding::Attested { spki_fingerprint }` is their verified match.

Cloud model fetches always request `include_tls_fingerprint=false`. They verify
the signer-and-nonce quote layout and deliberately do not claim a direct
client-to-model TLS connection.

## Error handling

Cloud client methods return `SdkError`, which distinguishes `ApiError` from
`VerificationError`. Local verification functions return `VerificationError`.
Match error variants when practical, or use `code()` and `retryable()` for a
stable machine-readable classification; never parse display text. See the
[error-handling section](./docs/verification-guide.md#handle-errors) for the
strict and non-strict completion-signature lookup behavior.
