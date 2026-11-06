# Python verification guide

Verify deployments before inference, then verify the returned response signature.

Use `InferenceClient` for verified Chat with optional encryption, or the standalone functions
when your application needs to inspect evidence and control each step.

## Verified Chat client

```python
from nearai_inference_sdk import InferenceClient


async def chat(api_key: str) -> None:
    async with InferenceClient(api_key, e2ee=True) as inference_client:
        completion = await inference_client.chat.completions.create(
            model='z-ai/glm-5.3-flash',
            messages=[{'role': 'user', 'content': 'Hello'}],
            max_completion_tokens=128,
        )
        verified = await inference_client.verify_response(completion.id)
        print(verified.signature_kind)
        print(completion.choices[0].message.content)
```

The Gateway client verifies Gateway evidence and every returned model report
before inference. Models without model attestation use Gateway-only (Incognito)
verification. E2EE and model deployment policies require model attestation.

`verified.attestations` contains all reports sharing the selected model signer.
For a Gateway receipt, use `verified.attestation`.

Set `e2ee=True` to encrypt supported Chat fields. `signing_algo` defaults to
`'ed25519'` and also accepts `'ecdsa'`.

Gateway requests use attested TLS pinning by default. For an application proxy,
set `GatewayVerificationOptions(include_spki_fingerprint=False)`.

Consume a stream before calling `verify_response()`:

```python
stream = await inference_client.chat.completions.create(
    model='z-ai/glm-5.3-flash',
    messages=[{'role': 'user', 'content': 'Hello'}],
    stream=True,
)
completion_id = None
async for chunk in stream:
    completion_id = chunk.id
    if chunk.choices:
        print(chunk.choices[0].delta.content or '', end='', flush=True)

if completion_id is None:
    raise RuntimeError('Stream returned no completion ID')
verified = await inference_client.verify_response(completion_id)
```

For an existing OpenAI integration, reuse the client's HTTP transport:

```python
from openai import AsyncOpenAI

async with InferenceClient(api_key, e2ee=True) as inference_client:
    async with AsyncOpenAI(
        api_key=api_key,
        base_url=inference_client.base_url,
        http_client=inference_client.http_client,
        max_retries=0,
    ) as openai_client:
        completion = await openai_client.chat.completions.create(
            model='z-ai/glm-5.3-flash',
            messages=[{'role': 'user', 'content': 'Hello'}],
        )
    verified = await inference_client.verify_response(completion.id)
```

For OpenAI with HTTPX2, install `openai[httpx2]` and use
`inference_client.httpx2_client`.

Configure credentials on `InferenceClient` and keep it open through response
verification.

### Verify before the first Chat request

Call `verify(model)` to check the deployment while your application prepares its
first request and obtain the verified evidence for display or inspection:

```python
async with InferenceClient(api_key, e2ee=True) as inference_client:
    attestations = await inference_client.verify('z-ai/glm-5.3-flash')
    print('Gateway TCB:', attestations.gateway.tcb_status)
    for model_attestation in attestations.models:
        print('Model TCB:', model_attestation.tcb_status)

    # Application code prepares the conversation after verification succeeds.
    completion = await inference_client.chat.completions.create(
        model='z-ai/glm-5.3-flash',
        messages=[{'role': 'user', 'content': 'Hello'}],
    )
    verified = await inference_client.verify_response(completion.id)
```

`verify(model)` returns the verified Gateway, all model reports, and the
verification time. `models` is empty for Gateway-only models. Set
`attestation_cache_time_to_live_ms` to control reuse; `0` verifies every request.
The default is one hour.

### Use OHTTP

Set `ohttp=True` to encapsulate Chat HTTP requests and responses to the Gateway:

```python
async with InferenceClient(api_key, ohttp=True) as inference_client:
    completion = await inference_client.chat.completions.create(
        model='z-ai/glm-5.3-flash',
        messages=[{'role': 'user', 'content': 'Hello'}],
    )
    verified = await inference_client.verify_response(completion.id)
    print(completion.choices[0].message.content)
```

OHTTP requires Ed25519 and an endpoint serving `/ohttp`.

OHTTP encrypts encapsulated requests and responses to the Gateway or Direct
endpoint. `Authorization` and configured forwarded headers remain on the outer
HTTP request. E2EE encrypts supported Chat fields to the model; both options can
be enabled independently or together.

Inference and response-verification calls use the same interfaces with OHTTP enabled.

### Connect through an application proxy

The proxy supplies the upstream NEAR AI credential. Configure its own
authentication through `headers`, and disable Gateway SPKI binding if the proxy
terminates TLS:

```python
from nearai_inference_sdk import GatewayVerificationOptions

async with InferenceClient(
    base_url='https://proxy.example/v1',
    headers={'Authorization': 'Bearer application-token'},
    e2ee=True,
    gateway_verification=GatewayVerificationOptions(include_spki_fingerprint=False),
) as inference_client:
    completion = await inference_client.chat.completions.create(
        model='z-ai/glm-5.3-flash',
        messages=[{'role': 'user', 'content': 'Hello'}],
    )
    verified = await inference_client.verify_response(completion.id)
```

Forward `/v1/model/{model}`, `/v1/attestation/report`, `/v1/chat/completions`,
`/v1/responses`, `/v1/messages`, and `/v1/signature/{id}`. For System One, also forward `POST /v1/systemone` and its
`X-Generation-Id` response header. Preserve URL-encoded model and signature IDs,
bodies, model-key routing, and encryption headers. A browser-facing proxy must
expose `X-Generation-Id` through CORS. The device verifies evidence and response
signatures; the proxy can only forward the encrypted Chat fields. System One
decision content is not encrypted by this SDK.

## System One decisions

`systemone.create()` sends one non-streaming decision request. Use an active
decision model and an endpoint serving `/v1/systemone`. The client verifies the
Gateway and all applicable model reports before sending the request.

```python
async with InferenceClient(api_key, base_url=base_url) as inference_client:
    result = await inference_client.systemone.create(
        {
            'model': decision_model,
            'state': {'message': 'Please explain this briefly.'},
            'questions': {
                'brief': {'type': 'noul', 'instructions': 'Should the answer be brief?'}
            },
        }
    )
    verified = await inference_client.verify_response(result.decision_id)
    print(result.data['answers'])
```

`result.decision_id` comes from `X-Generation-Id`. Pass it to `verify_response()`
before using the answers.

Use a Gateway client with E2EE and OHTTP disabled.

### Use the official TypeSafe SDK

Install `typesafe-sdk` and pass `inference.httpx2_client` to `AsyncTypeSafeClient`.
The TypeSafe API root excludes `/v1`; the NEAR client base URL includes `/v1/`.

```python
from nearai_inference_sdk import InferenceClient
from typesafe_sdk import AsyncTypeSafeClient, Noul, RetryPolicy


async def decide(api_key: str, model: str) -> None:
    async with InferenceClient(
        api_key,
        base_url='https://cloud-api.near.ai/v1/',
        e2ee=False,
        ohttp=False,
    ) as inference:
        async with AsyncTypeSafeClient(
            api_key=api_key,
            base_url='https://cloud-api.near.ai',
            http_client=inference.httpx2_client,
            compression=False,
            retry=RetryPolicy(max_retries=0),
            timeout=60,
        ) as typesafe:
            result = await typesafe.system_one(
                model=model,
                state='I was charged twice.',
                questions={'billing': Noul(instructions='Is this about billing?')},
            )
        receipt_id = result.raw_http_response.headers['x-generation-id']
        await inference.verify_response(receipt_id)
        print(result.nouls['billing'].noul)
```

Use a canonical Jev model ID from your endpoint's catalog. System One accepts
uncompressed, nonstreaming JSON requests; keep E2EE, OHTTP, request compression
and automatic inference retries disabled. Retry transient receipt lookups through
`verify_response(receipt_id)`.

Read the receipt ID from `raw_http_response.headers['x-generation-id']` and
verify it through the inference client.

See the [runnable official SDK example](../../examples/example-py/gateway/systemone_with_typesafe_sdk.py).

## Messages API

Gateway clients support Messages creation as JSON or SSE, with optional OHTTP
(Ed25519). Use field-level E2EE disabled.

Verify the message `id` after reading a JSON response, or `message_start.message.id`
after consuming the stream. Messages use Gateway receipts.

```python
message = await client.messages.create(
    model='anthropic/claude-haiku-4-5',
    max_tokens=128,
    messages=[{'role': 'user', 'content': 'Hello'}],
)
receipt = await client.verify_response(message.id)
print(receipt.signature_kind, message.content)
```

Set `stream=True` for typed Anthropic events. An external `AsyncAnthropic` can use
`http_client=client.http_client`, `base_url='https://cloud-api.near.ai'`, and
`max_retries=0`; the inference client's base URL includes `/v1/`. Its configured
authentication governs model reports, inference, and signature requests; Gateway attestation omits authentication headers.
See the [native example](../../examples/example-py/gateway/messages.py) and
[official SDK example](../../examples/example-py/gateway/messages_with_anthropic_sdk.py)
for JSON and streaming calls with receipt verification.

## Responses API

Gateway clients support Responses creation as JSON or SSE, with optional OHTTP
(Ed25519). Use field-level E2EE disabled.

Verify the response `id` after reading a JSON response, or `event.response.id`
after consuming the stream. Responses use Gateway receipts.

```python
response = await client.responses.create(
    model='z-ai/glm-5.3-flash',
    input='Reply with the word ok.',
    store=False,
)
receipt = await client.verify_response(response.id)
print(receipt.signature_kind, response.output_text)
```

Set `stream=True` and use `async for` for typed Responses events. An external
`AsyncOpenAI` client can use the same API through `http_client=client.http_client`.

## Direct model endpoints

`DirectInferenceClient` connects to a model endpoint and verifies every returned
model report. Direct clients are experimental and pin requests to the verified
model TLS fingerprints by default.

```python
from nearai_inference_sdk import DirectInferenceClient

async with DirectInferenceClient(
    'https://glm-5-3-flash.completions.near.ai/v1/',
    api_key=direct_api_key,
    e2ee=True,
) as direct_client:
    completion = await direct_client.chat.completions.create(
        model='z-ai/glm-5.3-flash',
        messages=[{'role': 'user', 'content': 'Hello'}],
    )
    verified = await direct_client.verify_response(completion.id)
```

Set `e2ee=True` to enable encryption. Streaming, OHTTP, and OpenAI integration
use the same interfaces as Gateway Chat.

For a manual workflow:

```python
from nearai_inference_sdk import (
    DirectAttestationClient,
    verify_direct_model_attestations,
    verify_direct_model_response,
)

direct_client = DirectAttestationClient(direct_base_url, api_key=direct_api_key)
fetched_attestations = await direct_client.fetch_model_attestations(
    signing_algo='ed25519'
)
verified = await verify_direct_model_attestations(fetched_attestations)

# Application code sends Chat and retains its exact request and response bytes.
signature = await direct_client.fetch_completion_signature(
    completion_id, signing_algo='ed25519'
)
matching = verify_direct_model_response(
    request_body,
    response_body,
    signature,
    verified.attestations,
)
```

## Standalone workflow

This flow verifies a NEAR TEE model. For Gateway-only models, use Gateway
attestation and Gateway response verification.

Bootstrap Gateway verification with `AttestationClient(api_key)`, then pass a
pinned HTTP client to a second `AttestationClient` for model reports, metadata,
and signatures. The application sends Chat and retains the exact bytes.

## Verification lifecycle

| Stage | SDK calls | What a successful result establishes |
| --- | --- | --- |
| 1. Verify deployments | `fetch_gateway_attestation` → `verify_gateway_attestation`; `fetch_model_attestations` → `verify_model_attestation` | The Gateway deployment and every returned target-model deployment satisfy your evidence and policy checks. |
| 2. Send a completion | Optional `prepare_e2ee_chat_request` | Your application sends Chat and retains the completion ID and exact encrypted request and response bytes. |
| 3. Verify the response signature | `fetch_completion_signature` → verifier selected by `signature.kind` | The selected model or Gateway signer signed those exact bytes. |

## 1. Verify Gateway and model deployments

Verify both deployments before sending the completion. Choose the signing
algorithm your application expects; this example uses ECDSA for all three
requests. Pass the same explicit algorithm to both attestation fetches and the
completion-signature fetch: the Gateway's report and signature endpoints have
different defaults.

```python
from nearai_inference_sdk import (
    AttestationClient,
    create_pinned_tls_client,
    verify_gateway_attestation,
    verify_model_attestation,
)

MODEL = 'z-ai/glm-5.3-flash'
SIGNING_ALGO = 'ecdsa'


async def verify_model_deployments(client: AttestationClient):
    fetched_model_attestations = await client.fetch_model_attestations(
        MODEL,
        signing_algo=SIGNING_ALGO,
    )
    if not fetched_model_attestations.attestations:
        raise RuntimeError('Gateway returned no model attestations')

    model_attestations = []
    for attestation in fetched_model_attestations.attestations:
        model_attestations.append(
            await verify_model_attestation(
                attestation,
                fetched_model_attestations.client_binding,
            )
        )
    return tuple(model_attestations)


bootstrap_client = AttestationClient(api_key)
fetched_gateway = await bootstrap_client.fetch_gateway_attestation(
    signing_algo=SIGNING_ALGO,
)
verified_gateway = await verify_gateway_attestation(
    fetched_gateway.attestation,
    fetched_gateway.client_binding,
)
assert verified_gateway.tls_binding.kind == 'attested'
async with create_pinned_tls_client(
    verified_gateway.tls_binding.spki_fingerprint
) as pinned_tls_client:
    client = AttestationClient(api_key, http_client=pinned_tls_client)
    model_attestations = await verify_model_deployments(client)
    # Send Chat with pinned_tls_client and verify its signature with client
    # before leaving this context. The later snippets describe those steps.
```

Keep the pinned HTTP client open through inference and response verification.

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

### Optional image build provenance

`fetch_image_provenance` retrieves Sigstore bundles; `verify_image_provenance`
checks the image digest and GitHub build policy. Set `ref` or `commit` to restrict
the source version.

Use `verify_deployment_image_provenance` in a deployment callback to check
required container images from measured Compose:

```python
from nearai_inference_sdk import (
    AttestationVerifiers,
    ImageProvenancePolicy,
    MeasuredDeployment,
    verify_deployment_image_provenance,
    verify_gateway_attestation,
)

image_policies = {
    'ghcr.io/example/gateway': ImageProvenancePolicy(
        repository='example/gateway',
        workflow='.github/workflows/build.yml',
        ref='refs/heads/main',
    ),
}


async def check_gateway_images(deployment: MeasuredDeployment) -> None:
    await verify_deployment_image_provenance(deployment.app_compose, image_policies)


verified_gateway = await verify_gateway_attestation(
    fetched_gateway.attestation,
    fetched_gateway.client_binding,
    verifiers=AttestationVerifiers(deployment=check_gateway_images),
)
```

For a reusable signing workflow, keep `repository`, `workflow`, `ref`, and
`commit` pointed at the source build. Set `signer_identity` to the exact reusable
workflow identity, for example:

```python
policy = ImageProvenancePolicy(
    repository='example/gateway',
    workflow='.github/workflows/build.yml',
    ref='refs/heads/main',
    signer_identity=(
        'https://github.com/example/build-workflows/'
        '.github/workflows/sign.yml@refs/tags/v1'
    ),
)
```

#### Model images deployed by Compose Manager

A model's measured `app_compose` can describe the launcher rather than containers
deployed later. Use the Compose Manager helper for the recorded model deployment:

```python
from nearai_inference_sdk import (
    ComposeManagerImagePolicy,
    ImageProvenancePolicy,
    MeasuredDeployment,
    ModelAttestationVerifiers,
    verify_compose_manager_deployment_image_provenance,
    verify_model_attestation,
)

model_image_policies = {
    'nearaidev/vllm-proxy-rs': ImageProvenancePolicy(
        repository='nearai/inference-proxy',
        workflow='.github/workflows/build.yml',
    ),
}


async def check_model_images(deployment: MeasuredDeployment) -> None:
    await verify_compose_manager_deployment_image_provenance(
        deployment,
        model_image_policies,
        compose_manager_image_policy=ComposeManagerImagePolicy(
            image_repository='nearaidev/compose-manager',
            repository='nearai/compose-manager',
            workflow='.github/workflows/build.yml',
        ),
    )


# Replace the model-verification loop inside verify_deployments with:
model_attestations = []
for attestation in fetched_model_attestations.attestations:
    model_attestations.append(
        await verify_model_attestation(
            attestation,
            fetched_model_attestations.client_binding,
            verifiers=ModelAttestationVerifiers(deployment=check_model_images),
        )
    )
```

This callback requires the configured image builds in the authenticated
deployment record, including the manager's startup image.

Use `compose_file` to select a project's file and `compose_repository` to change the
trusted repository. Configure this callback as `model_verification.verifiers.deployment`
on Gateway or Direct inference clients. The policy runs for every model report
and requires Compose Manager evidence in each one.

See the [API reference](./api-reference.md#verify_compose_manager_deployment_image_provenance)
for file selection and GitHub access options.

#### GitHub API access

Requests use `https://api.github.com` by default, with optional `github_token`
authentication. When using a GitHub token in a frontend is impractical, set
`github_api_url` to a GitHub-compatible endpoint on your backend. The backend
supplies the GitHub credentials; the SDK ignores `github_token` when
`github_api_url` is set.

The API base URL must be absolute HTTP(S), without credentials, a query, or
a fragment. The SDK preserves its path prefix and appends these GitHub API routes:

| Path appended to the API URL | Response |
| --- | --- |
| `/repos/{owner}/{repo}/attestations/{digest}?per_page=100` | GitHub JSON with inline `attestations[].bundle` and a `Link` header for pagination. |
| `/repos/{owner}/{repo}/contents/{file}?ref={commit}` | Exact file bytes, requested with `Accept: application/vnd.github.raw+json`. |

The custom endpoint must preserve GitHub status codes, pagination, and response bodies.

## 2. Send the completion and retain exact bytes

E2EE requests use `X-Encryption-Version: 3`, binding the reply public key and
field label through authenticated data. The endpoint must support v3. See the
[wire protocol](https://github.com/nearai/inference-proxy/blob/main/docs/e2ee.md)
for the format and supported fields.

After deployment verification succeeds, send the completion with the canonical
model ID. For model-signature compatibility, send `x-no-aliasing: true` and
retain the request bytes exactly as sent and response bytes exactly as received.
Do not parse and serialize them again: JSON whitespace, key order, SSE framing,
or text encoding changes the signed bytes.

Your application must retain:

- the canonical model ID;
- the completion ID returned by the Gateway;
- the exact request bytes; and
- the exact response bytes, including streaming framing when applicable.

### Encrypt a standalone request

After verifying all model attestations, select a public key from a verified result before
Chat. `find_model_attestations_for_signature` is used later, when the response
signature is available; it is not the encryption-key selector.

```python
import httpx
from nearai_inference_sdk import E2eeModelKey, prepare_e2ee_chat_request

selected_model_attestation = next(
    attestation
    for attestation in model_attestations
    if attestation.signer.signing_algo == SIGNING_ALGO
    and attestation.signing_public_key is not None
)
model_key = E2eeModelKey(
    signing_algo=selected_model_attestation.signer.signing_algo,
    public_key=selected_model_attestation.signing_public_key,
)
request = httpx.Request(
    'POST',
    'https://cloud-api.near.ai/v1/chat/completions',
    headers={'Authorization': f'Bearer {api_key}', 'Accept-Encoding': 'identity'},
    json={'model': MODEL, 'messages': [{'role': 'user', 'content': 'Hello'}]},
)
prepared = await prepare_e2ee_chat_request(request, model_key)
request_body = prepared.request.content
```

`prepared.request` contains the encrypted fields and E2EE/routing headers.
Send it using the same `pinned_tls_client` opened in stage 1, within its context.
Pass the response to `await prepared.decrypt_response(response)` for JSON or SSE
decryption. Retain the original encrypted response bytes separately for step 3.
Each prepared request owns a fresh response-decryption key.

See [`examples/example-py/gateway/chat_completions_bare.py`](../../examples/example-py/gateway/chat_completions_bare.py) for the
complete streaming and non-streaming flow, including byte capture and TLS pinning.

## 3. Verify the returned completion signature

Fetch the signature after the completion has reached its terminal state. A
provider signature selects the matching signer group from stage 1; a Gateway
signature uses the verified Gateway result. Multiple reports can share a signer.

```python
from nearai_inference_sdk import (
    find_model_attestations_for_signature,
    verify_gateway_response,
    verify_model_response,
)

# completion_id, request_body, and response_body came from your completion
# request. verified_gateway and model_attestations came from stage 1.
signature = await client.fetch_completion_signature(
    completion_id,
    signing_algo=SIGNING_ALGO,
)

if signature.kind == 'provider_tee':
    # Keep the routing/encryption key selected before sending the request.
    verify_model_response(
        request_body,
        response_body,
        signature,
        selected_model_attestation,
    )
    matching_attestations = find_model_attestations_for_signature(
        model_attestations,
        signature,
    )
else:
    verify_gateway_response(
        request_body,
        response_body,
        signature,
        verified_gateway,
    )
```

`matching_attestations` contains every verified report sharing the response signer.

`signature.kind` selects the response verifier:

| `signature.kind` | Call | Verifies |
| --- | --- | --- |
| `provider_tee` | `verify_model_response` | A verified model-serving TEE signer signed the exact request and response bytes. |
| `gateway` | `verify_gateway_response` | A verified Gateway signer signed the exact client-visible request and response bytes. |

## Set policy and trust roots

The default policy accepts `UpToDate`, `OutOfDate`, and `TDRelaunchAdvised`
TCB statuses. GPU evidence is verified when present; require it when your
application needs it:

```python
from nearai_inference_sdk import (
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

# Replace the model-verification loop inside verify_deployments with:
model_attestations = []
for attestation in fetched_model_attestations.attestations:
    model_attestations.append(
        await verify_model_attestation(
            attestation,
            fetched_model_attestations.client_binding,
            policy=policy,
            verifiers=verifiers,
        )
    )
```

`verify_deployment_release` is application code. It receives the measured
deployment and must raise for every deployment the application does not accept.
The SDK authenticates measured values; the callback decides which values are
acceptable.

Use `AttestationPolicy` for Gateway TCB requirements. Configure `verifiers.tdx_quote`
and `verifiers.gpu_evidence` to supply custom quote and GPU verifiers.

## Configure attestation service URLs

The built-in verifiers use these defaults:

| Service | URL |
| --- | --- |
| PCCS base | `https://api.trustedservices.intel.com` |
| NRAS evidence | `https://nras.attestation.nvidia.com/v3/attest/gpu` |
| NVIDIA signing keys | `https://nras.attestation.nvidia.com/.well-known/jwks.json` |

To use your own services, create verifier callbacks with custom URLs:

```python
from nearai_inference_sdk import (
    ModelAttestationVerifiers,
    create_tdx_quote_verifier,
    create_gpu_evidence_verifier,
)

verifiers = ModelAttestationVerifiers(
    tdx_quote=create_tdx_quote_verifier(
        pccs_url='https://attestation.example.com/pccs',
    ),
    gpu_evidence=create_gpu_evidence_verifier(
        nras_url='https://attestation.example.com/nras/v3/attest/gpu',
    ),
)
```

Pass `verifiers` to `verify_model_attestation`; Gateway verification accepts the
same quote callback through `AttestationVerifiers(tdx_quote=...)`.

DCAP builds the SGX and TDX collateral paths beneath `pccs_url`. `nras_url` is the
complete GPU evidence POST URL. Signing keys come from NVIDIA; set `jwks_url`
separately to use another trusted key source.

## Handle retrieval and verification errors

Request and evidence-selection failures use `ApiError`; verification failures use
`VerificationError`. Use `get_sdk_error()` for exceptions wrapped by OpenAI or
Anthropic; see the [API reference](./api-reference.md#errors-wrapped-by-official-sdks).

| Field | Meaning |
| --- | --- |
| `error.failure.code` | Stable code for an application to branch on. |
| `error.failure.details` (when present) | Code-specific diagnostic context. |
| `error.retryable` | Whether retrying the failed operation may succeed. |

```python
from nearai_inference_sdk import ApiError

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
```
