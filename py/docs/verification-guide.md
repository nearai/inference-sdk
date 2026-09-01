# Python verification guide

Use this SDK to verify NEAR AI Cloud attestations and completion signatures.

## Completion signature kinds

`fetch_completion_signature` exposes Cloud API's `signature_kind` as
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
| Audit a model deployment | You want to inspect a model-serving CVM's TCB status, measurements, GPU evidence, or deployment configuration. | `fetch_model_attestations` → `verify_model_attestation` | The quote, nonce, signer, measured deployment, and configured policy checks passed. | That a particular response came from this deployment, or that the client connected directly to its CVM. |
| Audit a Gateway endpoint | You want to inspect a Cloud API Gateway deployment and its TLS service identity. | `fetch_gateway_attestation` → `verify_gateway_attestation` | By default, the Gateway signer, deployment evidence, and quote-bound TLS identity match the TLS peer observed for the evidence request. | That a particular completion was served by the Gateway, or that a model executed the request. |
| Verify a model-issued response | The completion signature has `kind == 'provider_tee'`. | `fetch_completion_signature` → `fetch_model_attestations` → `find_model_attestation_for_signature` → `verify_model_attestation` → `verify_model_response` | A verified model TEE signer signed these exact request and response bytes. | The Gateway deployment or TLS endpoint. |
| Verify a Gateway-issued response | The completion signature has `kind == 'gateway'`. | `fetch_completion_signature` → `fetch_gateway_attestation` → `verify_gateway_attestation` → `verify_gateway_response` | A verified Gateway signer signed these exact request and response bytes. | That an attested model executed or generated the response. |

`fetch_model_attestations` preserves Cloud API's `model_attestations` array and
currently requires it to contain one item. It always requests
`include_tls_fingerprint=false`: model quote report data binds the signer and
fresh nonce, not client TLS. The result carries a `ModelClientBinding` for the
matching verification call.

`signing_algo` and `signing_address` are optional API request filters. They can
narrow what Cloud returns, but do not prove which result matches a completion.
For a `provider_tee` signature, always use
`find_model_attestation_for_signature` to perform the local signer selection.
`fetch_model_attestation_for_signature` is the convenience version that applies
those request filters and then performs the same local selection.

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
    fetch_completion_signature,
    fetch_model_attestations,
    find_model_attestation_for_signature,
    verify_model_attestation,
    verify_model_response,
)

# model, completion_id, request_body, and response_body were retained by your
# application's inference request.

signature = await fetch_completion_signature(api_key, completion_id)
if signature.kind != 'provider_tee':
    raise RuntimeError('Use the Gateway flow for this completion')

fetched_attestations = await fetch_model_attestations(api_key, model)
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
`fetch_model_attestations` creates a fresh client nonce, checks the service's
echo, and returns it inside `client_binding` with the evidence.

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

A Gateway attestation verifies a Cloud API Gateway deployment. Its TLS policy
selects both the evidence request and the quote layout used at verification.
`fetch_gateway_attestation` sends a fresh nonce, checks the echoed nonce, and
returns raw evidence, a `GatewayClientBinding`, and the resolved policy.

```python
from verifiable_ai_sdk import (
    fetch_gateway_attestation,
    verify_gateway_attestation,
)

gateway_evidence = await fetch_gateway_attestation(api_key)
verified_gateway_attestation = await verify_gateway_attestation(
    gateway_evidence.attestation,
    gateway_evidence.client_binding,
    policy=gateway_evidence.policy,
)
```

The default policy has `verify_tls_binding=True`. The native fetch helper
requests the TLS fingerprint and captures the SHA-256 SPKI fingerprint from the
TLS connection used for this exact HTTPS evidence request. Verification then
requires the quote-bound TLS fingerprint, the observed peer fingerprint, and
the client nonce to agree. A successful result has
`tls_binding.kind == 'attested'`.

If a runtime cannot observe the peer certificate, choose the no-TLS policy
before fetching evidence and pass the returned policy into verification:

```python
from verifiable_ai_sdk import GatewayAttestationPolicy

gateway_evidence = await fetch_gateway_attestation(
    api_key,
    policy=GatewayAttestationPolicy(verify_tls_binding=False),
)
verified_gateway_attestation = await verify_gateway_attestation(
    gateway_evidence.attestation,
    gateway_evidence.client_binding,
    policy=gateway_evidence.policy,
)
assert verified_gateway_attestation.tls_binding.kind == 'none'
```

With `verify_tls_binding=False`, the SDK sends
`include_tls_fingerprint=false`, does not require a peer fingerprint, and
verifies the signer-and-nonce report-data layout. It does not make or retain a
Gateway TLS identity claim.

For a signature with `kind == 'gateway'`, fetch evidence for the signature's
algorithm, verify it with the policy returned by that fetch, then verify the
response:

```python
from verifiable_ai_sdk import (
    fetch_gateway_attestation,
    verify_gateway_attestation,
    verify_gateway_response,
)

gateway_evidence = await fetch_gateway_attestation(
    api_key,
    signing_algo=signature.signer.signing_algo,
)
verified_gateway_attestation = await verify_gateway_attestation(
    gateway_evidence.attestation,
    gateway_evidence.client_binding,
    policy=gateway_evidence.policy,
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

`GatewayAttestationPolicy.verify_tls_binding` defaults to `True`. Set it to
`False` only before a Gateway fetch when the runtime cannot obtain the peer
certificate for that evidence request. Use the returned
`FetchedGatewayAttestation.policy` for the paired verification so its quote
layout stays aligned with the request.

`verifiers.quote` replaces the built-in Intel DCAP quote verifier. For model
evidence, the default NVIDIA verifier delegates to NVIDIA NRAS over HTTPS and
accepts its documented boolean overall result. It does not locally validate the
returned JWT/EAT signature. Set `verifiers.nvidia` when your trust model needs
local JWT/EAT validation, different trust roots, or another verification
service. Every verifier callback must return only for evidence it accepts.

## Handle signature lookup and verification errors

`fetch_completion_signature` is the strict path: it returns one completion
signature or raises a structured error. Use `lookup_completion_signature` when
the application needs to handle a successful unavailable envelope itself. It
returns either:

- `status == 'found'`, with a completion signature; or
- `status == 'unavailable'`, with the service error code and message.

A pending or unknown signature can instead produce HTTP 404. That remains a
retryable `api.http_status` error; it is not an unavailable lookup result.

Cloud API request helpers and evidence selection raise `ApiError` for request,
HTTP, response-format, nonce, unavailable-signature, or candidate-selection
failures. Verification functions and local input or signature-contract checks
raise `VerificationError`.

| Field | Meaning |
| --- | --- |
| `error.failure.code` | Stable code for an application to branch on. |
| `error.failure.details` (when present) | Code-specific diagnostic context. Do not parse `error.message`. |
| `error.retryable` | A new attempt at the failed external operation may succeed. It does not mean that re-verifying the same evidence will succeed or that an inference should be replayed. |

A 2xx unavailable response from `fetch_completion_signature` is an `ApiError`
with code `api.completion_signature_unavailable`: the strict helper could not
return the signature it promises. Prefer `lookup_completion_signature` when
unavailability is an ordinary application state.

```python
from verifiable_ai_sdk import (
    ApiError,
    VerificationError,
    fetch_completion_signature,
)

try:
    signature = await fetch_completion_signature(api_key, completion_id)
except ApiError as error:
    match error.failure.code:
        case 'api.completion_signature_unavailable':
            print('The completion has no usable signature')
        case 'api.http_status' if error.retryable:
            print('A later signature lookup may succeed')
        case _:
            raise
except VerificationError as error:
    print(error.failure.code)
