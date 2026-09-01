# NEAR AI verification SDK for Python

Verify NEAR AI Cloud attestation evidence and completion signatures. This
asynchronous SDK fetches and verifies evidence; your application sends the
completion request and retains its exact request and response bytes.

## What it verifies

- Model evidence: the Intel TDX quote, client nonce, signer, accepted TCB
  policy, runtime measurements, and measured deployment configuration. NVIDIA
  GPU evidence is verified when supplied and can be required by policy.
- Gateway evidence: the same deployment evidence, plus the Gateway TLS service
  identity bound into the quote. By default, verification also requires the
  TLS peer observed for the evidence request to match it.
- Completion signatures: the exact request and response bytes, signed by the
  signer established by the matching verified evidence.

Cloud API returns an explicit signature kind. `provider_tee` selects model
evidence and verifies a model-serving TEE signature. `gateway` selects Gateway
evidence and verifies a Gateway signature for the client-visible response; it
does not establish model execution.

The SDK does not send completion requests, choose retry behavior, or turn model
evidence into a client-to-model TLS claim.

Create an `AttestationClient` with the Cloud API key once. Its asynchronous
methods retrieve signatures and evidence, while selection and verification stay
as standalone functions. `client.fetch_gateway_attestation()` returns
`FetchedGatewayAttestation` with raw evidence, `client_binding`, and the
resolved `policy`. The native implementation obtains the SHA-256 SPKI
fingerprint from the TLS connection for that exact HTTPS request. Pass both the
binding and returned policy to `verify_gateway_attestation`; by default it
requires the observed peer to match the fingerprint authenticated in the quote.
A runtime
without peer-certificate access must fetch with
`GatewayAttestationPolicy(verify_tls_binding=False)`, then pass the returned
policy to verification. That path requests no TLS fingerprint, verifies the
signer-and-nonce quote layout, and returns `GatewayTlsBinding(kind='none')`.
`GatewayAttestation.spki_fingerprint` is Gateway-reported,
`GatewayClientBinding.spki_fingerprint` is client-observed, and a successful
`GatewayTlsBinding.spki_fingerprint` is their verified match.

## Documentation

- [Verification guide](./docs/verification-guide.md) covers model and Gateway
  flows, policy configuration, and error handling.
- [API reference](./docs/api-reference.md) lists `AttestationClient`,
  verification functions, parameters, and result fields.

## Errors

Cloud retrieval and evidence-selection failures raise `ApiError`. Local input,
cryptographic, policy, and binding failures raise `VerificationError`. For
both, branch on `error.failure.code` and inspect `error.failure.details` only
when it is present; never parse the human-readable message.

`error.retryable` means a new attempt at the failed external operation may
succeed. It does not mean that re-verifying the same evidence will succeed or
that an inference should be replayed.

`client.fetch_completion_signature()` is the strict method: a successful Cloud
API unavailable envelope raises `ApiError` with
`api.completion_signature_unavailable`. Use
`client.lookup_completion_signature()` when that unavailable state is a normal
application outcome.

## Development checks

From this directory:

```sh
uv sync
make lint
uv build
```

The test suite is deterministic and uses local fixtures; it does not contact
Cloud API, Intel PCCS, or NVIDIA NRAS.
