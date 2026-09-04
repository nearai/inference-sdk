# verifiable-ai-sdk (Rust)

`verifiable-ai-sdk` verifies three distinct kinds of NEAR AI Cloud evidence:

- a Gateway deployment attestation, including its TLS endpoint binding when
  available;
- a model-serving deployment attestation; and
- a completion signature over exact request and response bytes.

The recommended lifecycle is:

1. Verify the Gateway deployment you intend to use.
2. Verify the canonical model deployment you intend to use.
3. Send the chat request and retain its exact request and response bytes.
4. Fetch the completion signature and verify that response receipt against the
   corresponding preflight result.

The Gateway and model checks are both useful preflight controls. A completion
signature's `CompletionSignatureKind` only selects the final response-receipt
verifier:

| Kind | Verify with | A successful receipt proves |
| --- | --- | --- |
| `ProviderTee` | `verify_model_response` | The verified model signer signed the exact request and response bytes. |
| `Gateway` | `verify_gateway_response` | The verified Gateway signer signed the exact client-visible request and response bytes. |

The current Cloud API evidence does not yet provide a cryptographic chain from
a particular model response through a Gateway transformation to the final
response. In particular, preflight Gateway and model attestations do not prove
that they served a particular chat completion. [cloud-api#986](https://github.com/nearai/cloud-api/issues/986)
tracks a provider-signature plus Gateway-receipt design for that complete
chain. Verify both deployments before the request, but do not claim more than
the evidence currently proves.

## Documentation

- [Verification guide](./docs/verification-guide.md) walks through the
  preflight, chat, and response-receipt stages.
- [API reference](./docs/api-reference.md) lists the client, verification
  functions, return values, policies, and callback traits.
- [`examples/example-rs`](../examples/example-rs) is a runnable end-to-end
  example.

## Install

```toml
[dependencies]
verifiable-ai-sdk = "0.1"
```

Retain the exact bytes sent to and received from the completion endpoint. The
SDK verifies those bytes without reserializing them.

Gateway SPKI fingerprint evidence is requested by default. The Rust client
captures the peer certificate for that same HTTPS attestation request. A
runtime without peer-certificate access must use
`GatewayAttestationFetchOptions { include_spki_fingerprint: false, ..Default::default() }`.
That still verifies Gateway deployment evidence, but makes no TLS identity
claim. Model attestation fetches always omit TLS fingerprint evidence because
Cloud API, rather than the client, connects to the model.

## Error handling

Cloud client methods return `SdkError`, which distinguishes `ApiError` from
`VerificationError`. Local verification functions return `VerificationError`.
Match error variants when practical, or use `code()` and `retryable()` for a
stable machine-readable classification; never parse display text. See the
[error-handling section](./docs/verification-guide.md#handle-errors) for
completion-signature failures.
