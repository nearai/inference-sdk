# verifiable-ai-sdk (Rust)

`verifiable-ai-sdk` verifies NEAR AI Cloud deployment attestations and the
completion signatures returned by Cloud API. It separates evidence retrieval,
deployment verification, and verification of an exact completion's request and
response bytes.

## Documentation

- [Verification guide](./docs/verification-guide.md) explains which evidence
  and response-verification path to use for `provider_tee` and `gateway`
  signatures.
- [API reference](./docs/api-reference.md) lists Cloud request builders,
  functions, return values, policies, and callback traits.

## Install

```toml
[dependencies]
verifiable-ai-sdk = "0.1"
```

The guide includes complete model and Gateway verification flows. In both
cases, retain the exact bytes sent to and received from the completion endpoint:
the SDK verifies those bytes without reserializing them.

Gateway verification requires a client-observed TLS peer by default. The Rust
fetch helper captures the peer certificate for its HTTPS evidence request and
returns its SHA-256 SPKI fingerprint in `FetchedGatewayAttestation.client_binding`.
Callers without peer-certificate access must explicitly disable that check with
`GatewayAttestationPolicy { verify_peer_tls_binding: false, ..Default::default() }`.
That path still verifies the nonce and quote-bound TLS identity, returns
`GatewayTlsBinding::Attested`, and ignores any supplied peer fingerprint.

## Error handling

Cloud request helpers return `SdkError`, which distinguishes `ApiError` from
`VerificationError`. Local verification functions return `VerificationError`.
Match error variants when practical, or use `code()` and `retryable()` for a
stable machine-readable classification; never parse display text. See the
[error-handling section](./docs/verification-guide.md#handle-errors) for the
strict and non-strict completion-signature lookup behavior.
