# Python verification guide

Use this SDK to verify NEAR AI Cloud deployment attestations and completion
signatures. The recommended workflow starts with deployment evidence, then
sends a completion, then verifies the signature returned for that completion.
`signature.kind` is used only in the final step to select the right response
verifier.

Create `client = AttestationClient(api_key)` once. It retrieves Cloud API
evidence and signatures; your application sends the completion request and
keeps the exact bytes it sends and receives.

## Verification lifecycle

| Stage | SDK calls | What a successful result establishes |
| --- | --- | --- |
| 1. Verify deployments | `fetch_gateway_attestation` → `verify_gateway_attestation`; `fetch_model_attestations` → `verify_model_attestation` | The Gateway deployment and target model deployment each satisfy your evidence and policy checks. |
| 2. Send a completion | None | Your application retains the canonical model ID, completion ID, and exact request and response bytes. |
| 3. Verify the response signature | `fetch_completion_signature` → verifier selected by `signature.kind` | The selected model or Gateway signer signed those exact bytes. |

Stage 1 is useful before inference: it lets an application reject a deployment
that does not meet its TCB, measurement, GPU, or Gateway-TLS requirements.
Each fetch is a fresh observation, so the application decides when to refresh
that evidence.

## 1. Verify Gateway and model deployments

Verify both deployments before sending the completion. Choose the signing
algorithm your application expects; this example uses ECDSA for all three
requests.

```python
from verifiable_ai_sdk import (
    AttestationClient,
    verify_gateway_attestation,
    verify_model_attestation,
)

MODEL = 'z-ai/glm-5.2'
SIGNING_ALGO = 'ecdsa'


async def verify_deployments(client: AttestationClient):
    fetched_gateway = await client.fetch_gateway_attestation(
        signing_algo=SIGNING_ALGO,
    )
    verified_gateway = await verify_gateway_attestation(
        fetched_gateway.attestation,
        fetched_gateway.client_binding,
    )

    fetched_model = await client.fetch_model_attestations(
        MODEL,
        signing_algo=SIGNING_ALGO,
    )
    # Cloud API currently returns exactly one model attestation per request.
    verified_model = await verify_model_attestation(
        fetched_model.attestations[0],
        fetched_model.client_binding,
    )
    return verified_gateway, verified_model
```

`fetch_gateway_attestation()` and `fetch_model_attestations()` target the same
Cloud API report endpoint, but ask for evidence with different client bindings:

- Gateway evidence requests an SPKI fingerprint by default. The Python SDK
  captures the peer fingerprint from that same HTTPS evidence request, and
  `verify_gateway_attestation` checks that the peer, quote, signer, and nonce
  agree.
- Model evidence requests no TLS fingerprint. The client connects to the
  Gateway rather than directly to a model CVM, so model verification checks the
  signer and nonce binding without making a client-to-model TLS claim.

The fetch helpers generate fresh nonces and reject a response whose echoed
nonce does not match. `verify_*_attestation` then verifies the quote,
measurements, deployment configuration, and policy.

### Gateway TLS identity

The default Gateway fetch requests and verifies quote-bound TLS identity:

```python
fetched_gateway = await client.fetch_gateway_attestation(
    signing_algo=SIGNING_ALGO,
)
verified_gateway = await verify_gateway_attestation(
    fetched_gateway.attestation,
    fetched_gateway.client_binding,
)
assert verified_gateway.tls_binding.kind == 'attested'
```

If the runtime cannot observe the peer certificate, request evidence without an
SPKI fingerprint instead:

```python
fetched_gateway = await client.fetch_gateway_attestation(
    signing_algo=SIGNING_ALGO,
    include_spki_fingerprint=False,
)
verified_gateway = await verify_gateway_attestation(
    fetched_gateway.attestation,
    fetched_gateway.client_binding,
)
assert verified_gateway.tls_binding.kind == 'none'
```

The second form still verifies the Gateway quote, signer, nonce, deployment,
and policy. It does not make a claim about the TLS peer serving the evidence
request.

## 2. Send the completion and retain exact bytes

After deployment verification succeeds, send the completion with the canonical
model ID. For model-signature compatibility, send `x-no-aliasing: true` and
retain the request bytes exactly as sent and response bytes exactly as received.
Do not parse and serialize them again: JSON whitespace, key order, SSE framing,
or text encoding changes the signed bytes.

Your application must retain:

- the canonical model ID;
- the completion ID returned by Cloud API;
- the exact request bytes; and
- the exact response bytes, including streaming framing when applicable.

The SDK intentionally does not make the completion request or decide retry
behavior for it.

## 3. Verify the returned completion signature

Fetch the signature after the completion has reached its terminal state. Pass
the verified deployment result from stage 1 to the verifier selected by the
returned kind.

```python
from verifiable_ai_sdk import (
    verify_gateway_response,
    verify_model_response,
)

# completion_id, request_body, and response_body came from your completion
# request. verified_gateway and verified_model came from stage 1.
signature = await client.fetch_completion_signature(
    completion_id,
    signing_algo=SIGNING_ALGO,
)

if signature.kind == 'provider_tee':
    verify_model_response(
        request_body,
        response_body,
        signature,
        verified_model,
    )
else:
    verify_gateway_response(
        request_body,
        response_body,
        signature,
        verified_gateway,
    )
```

Cloud API provides two signature kinds. They are different response signatures,
not two top-level deployment workflows:

| `signature.kind` | Call | A successful result establishes | It does not establish |
| --- | --- | --- | --- |
| `provider_tee` | `verify_model_response` | A verified model-serving TEE signer signed the exact request and response bytes. | Which Gateway deployment or TLS endpoint returned them. |
| `gateway` | `verify_gateway_response` | A verified Gateway signer signed the exact client-visible request and response bytes. | That an attested model executed or generated them. |

Cloud API can rewrite a response before returning it, for example while
normalizing a stream for OpenAI compatibility. A provider signature over the
upstream bytes cannot verify rewritten bytes, so Cloud API may return a
`gateway` signature for the final client-visible bytes. Always use the kind
returned for that completion; never infer it from signed text.

## Current evidence boundary

The two preflight attestations and the single completion signature do not yet
form a complete model-to-Gateway-to-final-bytes cryptographic chain.

- With `provider_tee`, model evidence and the model signature bind the
  model signer to the exact bytes, but do not bind those bytes to the Gateway
  deployment verified separately.
- With `gateway`, Gateway evidence and the Gateway signature bind the Gateway
  signer to the final client-visible bytes, but do not prove model execution or
  connect an upstream model response to those bytes.

Consequently, successfully verifying both preflight deployments must not be
presented as proof that they served the same inference. [Cloud API issue #986](https://github.com/nearai/cloud-api/issues/986)
tracks the missing chain: preserving a provider signature and adding a Gateway
receipt that binds the upstream and final response hashes for the same
inference.

## Set policy and trust roots

The default policy accepts `UpToDate` and `OutOfDate` TCB statuses. GPU evidence
is verified when present; require it when your application needs it:

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

verified_model = await verify_model_attestation(
    fetched_model.attestations[0],
    fetched_model.client_binding,
    policy=policy,
    verifiers=verifiers,
)
```

`verify_deployment_release` is application code. It receives the measured
deployment and must raise for every deployment the application does not accept.
The SDK authenticates measured values; the callback decides which values are
acceptable.

`verify_gateway_attestation` accepts `AttestationPolicy` when an application
needs to restrict Gateway TCB statuses. `verifiers.quote` replaces the built-in
Intel DCAP quote verifier. For model evidence, the default NVIDIA verifier
delegates to NVIDIA NRAS over HTTPS and accepts its documented boolean overall
result. Set `verifiers.nvidia` when your trust model requires local JWT/EAT
validation, different trust roots, or another verification service. Every
verifier callback must return only for evidence it accepts.

## Handle retrieval and verification errors

`client.fetch_completion_signature()` returns one signature or raises a
structured error. A 2xx unavailable envelope raises `ApiError` with
`api.completion_signature_unavailable`; its details contain the service's
`providerErrorCode` and `providerMessage`.

An HTTP 404 raises `api.http_status` and remains retryable. It means Cloud API
has no stored signature for that ID at that time. Retry only when the
application has reason to expect a later signature, such as before the
completion has reached its terminal state.

`AttestationClient` methods and evidence selection raise `ApiError` for
request, HTTP, response-format, nonce, unavailable-signature, or
candidate-selection failures. Verification functions and local input or
signature-contract checks raise `VerificationError`.

| Field | Meaning |
| --- | --- |
| `error.failure.code` | Stable code for an application to branch on. |
| `error.failure.details` (when present) | Code-specific diagnostic context. Do not parse `error.message`. |
| `error.retryable` | A new attempt at the failed external operation may succeed. It does not mean that re-verifying the same evidence will succeed or that an inference should be replayed. |

```python
from verifiable_ai_sdk import ApiError, VerificationError

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
