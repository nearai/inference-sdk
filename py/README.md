# NEAR AI verification SDK for Python

Verify NEAR AI Cloud deployment attestations and completion signatures. This
asynchronous SDK retrieves and verifies evidence; your application sends the
completion request and retains its exact request and response bytes.

## Recommended lifecycle

For a completion, use three stages:

1. Before sending it, verify the NEAR AI Cloud Gateway deployment and every
   returned target-model deployment.
2. Send the completion and retain its canonical model ID, completion ID, and
   exact request and response bytes.
3. Fetch the completion signature and use its `kind` to verify the exact
   response bytes with the already verified model or Gateway evidence.

`fetch_model_attestations()` can return zero or multiple candidates. Reject an
empty result, verify every returned candidate, and retain every verified result
for receipt verification.

The deployment checks are useful admission and audit evidence before an
inference. They are independent checks: do not treat them as proof that a
particular completion travelled from that model deployment through that
Gateway deployment.

## What it verifies

- Model deployment evidence: the Intel TDX quote, client nonce, signer,
  accepted TCB policy, runtime measurements, and measured deployment
  configuration. NVIDIA GPU evidence is verified when supplied and can be
  required by policy.
- Gateway deployment evidence: the same deployment evidence, plus the Gateway
  TLS service identity bound into the quote. By default, verification also
  requires the TLS peer observed for the evidence request to match it.
- A completion signature: the exact request and response bytes signed by the
  signer named in the returned signature.
- Optional image build provenance: Sigstore signatures, transparency-log evidence,
  and a GitHub build identity selected by the caller. No publisher or version
  approval policy is provided by default.

The Gateway returns an explicit kind for each completion signature:

| `signature.kind` | Response verification establishes | It does not establish |
| --- | --- | --- |
| `provider_tee` | A verified model-serving TEE signer signed the exact request and response bytes. | The Gateway deployment or TLS identity that returned those bytes. |
| `gateway` | A verified Gateway signer signed the exact client-visible request and response bytes. | That an attested model executed or generated those bytes. |

The Gateway currently exposes one signature for a completion. Separately
verified model and Gateway deployments plus that one signature do **not** form a
complete cryptographic chain from model execution through Gateway processing to
the final bytes. In particular, the current Gateway signature over rewritten
bytes has no provider-response link. [cloud-api#986](https://github.com/nearai/cloud-api/issues/986)
tracks the proposed provider signature plus Gateway receipt chain.

The SDK does not send completion requests, choose retry behavior, or turn model
evidence into a client-to-model TLS claim.

Create an `AttestationClient` with the Gateway API key once. Its asynchronous
methods retrieve signatures and evidence; selection and verification are
standalone functions. `client.fetch_gateway_attestation()` returns a
`FetchedGatewayAttestation` with raw attestation and `client_binding`. By
default, it requests the Gateway's SPKI fingerprint and the native
implementation obtains the SHA-256 SPKI fingerprint from the TLS connection
for that exact HTTPS request. Pass both values to
`verify_gateway_attestation`; an attestation with an SPKI fingerprint requires
the observed peer to match the fingerprint authenticated in the quote. A
runtime without peer-certificate access can fetch with
`include_spki_fingerprint=False`. That path requests no TLS fingerprint,
verifies the signer-and-nonce quote layout, and returns
`GatewayTlsBinding(kind='none')`.
`GatewayAttestation.spki_fingerprint` is Gateway-reported,
`GatewayClientBinding.spki_fingerprint` is client-observed, and a successful
`GatewayTlsBinding.spki_fingerprint` is their verified match.

## Documentation

- [Verification guide](./docs/verification-guide.md) describes the
  deployment-first workflow, policy configuration, completion signatures, and
  error handling.
- [API reference](./docs/api-reference.md) lists `AttestationClient`,
  verification functions, parameters, and result fields.

## Errors

Handle retrieval and verification at separate call sites.
`AttestationClient` and evidence-selection failures raise `ApiError`, including
invalid helper input. Explicit verification functions raise
`VerificationError` for local input, cryptographic, policy, and binding
failures. Each handler has one SDK error type. Branch on its
`error.failure.code` and inspect `error.failure.details` only when it is
present; never parse the human-readable message.

`error.retryable` means a new attempt at the failed external operation may
succeed. It does not mean that re-verifying the same evidence will succeed or
that an inference should be replayed.

`client.fetch_completion_signature()` returns a completion signature or raises
`ApiError`. A 2xx response that reports an unavailable signature raises
`api.completion_signature_unavailable`; its details preserve the provider's
error code and message.

## Development checks

From this directory:

```sh
uv sync
make lint
uv build
```

The test suite is deterministic and uses local fixtures; it does not contact
the NEAR AI Cloud Gateway, Intel PCCS, or NVIDIA NRAS.
