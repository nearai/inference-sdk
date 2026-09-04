# Python verification guide

Use this SDK to verify NEAR AI Cloud attestations and completion signatures.
Create `client = AttestationClient(api_key)` once to retrieve Cloud API
signatures and evidence; selection and verification remain standalone
functions.

## Completion signature kinds

`client.fetch_completion_signature()` exposes Cloud API's `signature_kind` as
`signature.kind`. Cloud API selects one of two kinds for each returned
signature. The kind selects a verification path: it changes the trust boundary
and what a successful verification establishes, not only which key signed.

| `signature.kind` | Trust boundary | A successful response verification establishes | It does not establish |
| --- | --- | --- | --- |
| `provider_tee` | The model-serving TEE | A verified model TEE signer signed the exact request and response bytes. | The Cloud API Gateway's deployment or TLS identity. |
| `gateway` | The NEAR AI Cloud Gateway TEE | A verified Gateway signer signed the exact client-visible request and response bytes. | That an attested model executed or generated the response. |

Cloud API may rewrite a response before returning it, such as when it
normalizes a stream for OpenAI compatibility. Rewriting changes the bytes the
client receives, so a byte-exact provider signature cannot verify them. Cloud
API can return a `gateway` signature for those rewritten bytes. Use the kind
returned for that completion; a `gateway` signature is not evidence of model
execution.

## Choose what to verify

Both model and Gateway attestations can be verified independently. A completion
signature is needed only when the claim is about a particular response.

| Goal | Use it when | SDK calls | A successful result establishes | It does not establish |
| --- | --- | --- | --- | --- |
| Audit a model deployment | You want to inspect a model-serving CVM's TCB status, measurements, GPU evidence, or deployment configuration. | `client.fetch_model_attestations` → `verify_model_attestation` | The quote, nonce, signer, measured deployment, and configured policy checks passed. | That a particular response came from this deployment, or that the client connected directly to its CVM. |
| Audit a Gateway endpoint | You want to inspect a Cloud API Gateway deployment and its TLS service identity. | `client.fetch_gateway_attestation` → `verify_gateway_attestation` | By default, the Gateway signer, deployment evidence, and quote-bound TLS identity match the TLS peer observed for the evidence request. | That a particular completion was served by the Gateway, or that a model executed the request. |
| Verify a model-issued response | The completion signature has `kind == 'provider_tee'`. | `client.fetch_completion_signature` → `client.fetch_model_attestations` → `find_model_attestation_for_signature` → `verify_model_attestation` → `verify_model_response` | A verified model TEE signer signed these exact request and response bytes. | The Gateway deployment or TLS endpoint. |
| Verify a Gateway-issued response | The completion signature has `kind == 'gateway'`. | `client.fetch_completion_signature` → `client.fetch_gateway_attestation` → `verify_gateway_attestation` → `verify_gateway_response` | A verified Gateway signer signed these exact request and response bytes. | That an attested model executed or generated the response. |

`client.fetch_model_attestations()` preserves Cloud API's `model_attestations`
array and currently requires it to contain one item. It always requests
`include_tls_fingerprint=false`: model quote report data binds the signer and
fresh nonce, not client TLS. The result carries a `ModelClientBinding` for the
matching verification call.

`signing_algo` and `signing_address` are optional API request filters. They can
narrow what Cloud returns, but do not prove which result matches a completion.
For a `provider_tee` signature, always use
`find_model_attestation_for_signature` to perform the local signer selection.
`client.fetch_model_attestation_for_signature()` is the convenience version
that applies those request filters and then performs the same local selection.

For complete parameter and result definitions, see the
[API reference](./api-reference.md).

## Verify a model response

Use this flow only when the completion signature has `kind == 'provider_tee'`.

The SDK does not send inference requests. Before this flow, your application
must have sent a completion with `x-no-aliasing: true` using a canonical model
ID, then retained that model ID, the completion ID, and the exact request and
response bytes. Do not parse and serialize those bytes again: changing JSON
whitespace, key ordering, framing, or encoding changes the signed bytes.

```python
from verifiable_ai_sdk import (
    AttestationClient,
    find_model_attestation_for_signature,
    verify_model_attestation,
    verify_model_response,
)

# model, completion_id, request_body, and response_body were retained by your
# application's inference request.
client = AttestationClient(api_key)

signature = await client.fetch_completion_signature(completion_id)
if signature.kind != 'provider_tee':
    raise RuntimeError('Use the Gateway flow for this completion')

fetched_attestations = await client.fetch_model_attestations(model)
attestation = find_model_attestation_for_signature(
    fetched_attestations.attestations,
    signature,
)
verified_attestation = await verify_model_attestation(
    attestation,
    fetched_attestations.client_binding,
)
verify_model_response(
    request_body,
    response_body,
    signature,
    verified_attestation,
)
```

When `verify_model_response` returns, the model signature is valid for those
exact bytes and its signing identity matches `verified_attestation.signer`.
`client.fetch_model_attestations()` creates a fresh client nonce, checks the
service's echo, and returns it inside `client_binding` with the evidence.

`verify_model_response` verifies response bytes and matches the signature to
the verified signer; it does not repeat quote, policy, or deployment
verification. Call `verify_model_attestation` first. Its result is ordinary
data, so your application decides when raw evidence must be verified again
after storage or transfer.

### What the model-attestation result contains

`verify_model_attestation` checks the nonce, Intel TDX quote, TCB policy,
runtime measurements, and model signing identity. Its result includes:

- `signer`, the identity that must match the completion signature;
- `tcb_status` and `advisory_ids` from quote verification;
- `deployment`, containing measured configuration text and runtime measurements;
- `gpu_evidence`, either `verified` or `not_provided`; and
- `deployment_provenance`, either `verified` when a deployment verifier ran
  successfully or `not_checked` otherwise.

Model verification deliberately has no TLS-binding result. The client TLS
connection terminates at the Gateway, so a model attestation cannot establish a
client-to-model TLS claim.

## Verify a Gateway attestation

A Gateway attestation verifies a Cloud API Gateway deployment.
`client.fetch_gateway_attestation()` sends a fresh nonce, checks the echoed
nonce, and returns raw attestation and a `GatewayClientBinding`.

```python
from verifiable_ai_sdk import (
    AttestationClient,
    verify_gateway_attestation,
)

client = AttestationClient(api_key)
fetched_gateway_attestation = await client.fetch_gateway_attestation()
verified_gateway_attestation = await verify_gateway_attestation(
    fetched_gateway_attestation.attestation,
    fetched_gateway_attestation.client_binding,
)
```

By default, the fetch helper requests the Gateway TLS fingerprint and captures
the SHA-256 SPKI fingerprint from the TLS connection used for this exact HTTPS
evidence request. Verification uses the TLS-bound report-data layout whenever
the returned attestation has an SPKI fingerprint. It then requires the
quote-bound fingerprint, observed peer fingerprint, and client nonce to agree.
A successful result has
`tls_binding.kind == 'attested'`.

If a runtime cannot observe the peer certificate, disable SPKI retrieval before
fetching:

```python
from verifiable_ai_sdk import AttestationClient, verify_gateway_attestation

client = AttestationClient(api_key)
fetched_gateway_attestation = await client.fetch_gateway_attestation(
    include_spki_fingerprint=False,
)
verified_gateway_attestation = await verify_gateway_attestation(
    fetched_gateway_attestation.attestation,
    fetched_gateway_attestation.client_binding,
)
assert verified_gateway_attestation.tls_binding.kind == 'none'
```

With `include_spki_fingerprint=False`, the SDK requests no TLS fingerprint,
does not capture a peer fingerprint, and verifies the signer-and-nonce
report-data layout. It does not make a Gateway TLS identity claim.

For a signature with `kind == 'gateway'`, fetch evidence for the signature's
algorithm, verify it, then verify the response:

```python
from verifiable_ai_sdk import (
    AttestationClient,
    verify_gateway_attestation,
    verify_gateway_response,
)

client = AttestationClient(api_key)
fetched_gateway_attestation = await client.fetch_gateway_attestation(
    signing_algo=signature.signer.signing_algo,
)
verified_gateway_attestation = await verify_gateway_attestation(
    fetched_gateway_attestation.attestation,
    fetched_gateway_attestation.client_binding,
)
verify_gateway_response(
    request_body,
    response_body,
    signature,
    verified_gateway_attestation,
)
```

This verifies Gateway-service provenance and integrity for exact completion
bytes: the signature is valid and its signer is bound to verified Gateway
deployment evidence. It does not establish model execution; use a
`provider_tee` signature and model evidence for that claim.

## Set policy and trust roots

The default policy accepts `UpToDate` and `OutOfDate` TCB statuses. GPU
evidence is verified when the report provides it; a report without GPU evidence
is accepted by default. Require GPU evidence when your application needs it:

```python
from verifiable_ai_sdk import (
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    verify_model_attestation,
)

policy = ModelAttestationPolicy(
    accepted_tcb_statuses=('UpToDate',),
    gpu_evidence='required',
)
verifiers = ModelAttestationVerifiers(
    deployment=verify_deployment_release,
)

verified_attestation = await verify_model_attestation(
    attestation,
    fetched_attestations.client_binding,
    policy=policy,
    verifiers=verifiers,
)
```

`verify_deployment_release` is application code. It receives the measured
deployment and must raise for every deployment the application does not accept.
The SDK authenticates the measured values, but the callback decides which
deployments are acceptable.

`verify_gateway_attestation` accepts `AttestationPolicy` when an application
needs to restrict accepted Gateway TCB statuses. The report-data layout follows
whether the fetched attestation contains an SPKI fingerprint, not the policy.

`verifiers.quote` replaces the built-in Intel DCAP quote verifier. For model
evidence, the default NVIDIA verifier delegates to NVIDIA NRAS over HTTPS and
accepts its documented boolean overall result. It does not locally validate the
returned JWT/EAT signature. Set `verifiers.nvidia` when your trust model needs
local JWT/EAT validation, different trust roots, or another verification
service. Every verifier callback must return only for evidence it accepts.

## Handle signature retrieval and verification errors

`client.fetch_completion_signature()` returns one completion signature or
raises a structured error. A successful unavailable response raises `ApiError`
with `api.completion_signature_unavailable`; its details contain the service's
`providerErrorCode` and `providerMessage`.

An HTTP 404 also raises `api.http_status` and remains retryable. It means Cloud
API has no stored signature for that ID at that time. Retry only when the
application has reason to expect a later signature, such as before the
completion has reached its terminal state.

`AttestationClient` methods and evidence selection raise `ApiError` for request,
HTTP, response-format, nonce, unavailable-signature, or candidate-selection
failures. Verification functions and local input or signature-contract checks
raise `VerificationError`.

| Field | Meaning |
| --- | --- |
| `error.failure.code` | Stable code for an application to branch on. |
| `error.failure.details` (when present) | Code-specific diagnostic context. Do not parse `error.message`. |
| `error.retryable` | A new attempt at the failed external operation may succeed. It does not mean that re-verifying the same evidence will succeed or that an inference should be replayed. |

```python
from verifiable_ai_sdk import (
    AttestationClient,
    ApiError,
    VerificationError,
)

client = AttestationClient(api_key)

try:
    signature = await client.fetch_completion_signature(completion_id)
except ApiError as error:
    match error.failure.code:
        case 'api.completion_signature_unavailable':
            print('The completion has no usable signature')
        case 'api.http_status' if error.retryable:
            print('A later signature request may succeed')
        case _:
            raise
except VerificationError as error:
    print(error.failure.code)
