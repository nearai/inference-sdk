# Python verification guide

Use this SDK to verify NEAR AI Cloud deployment attestations and completion
signatures. The recommended workflow starts with deployment evidence, then
sends a completion, then verifies the signature returned for that completion.
`signature.kind` is used only in the final step to select the right response
verifier.

Use `InferenceClient` for verified, encrypted Chat, or the standalone functions
when your application needs to inspect evidence and control each step.

## Verified Chat client

```python
from nearai_inference_sdk import InferenceClient


async def chat(api_key: str) -> None:
    async with InferenceClient(api_key) as inference_client:
        completion = await inference_client.chat.completions.create(
            model='z-ai/glm-5.3-flash',
            messages=[{'role': 'user', 'content': 'Hello'}],
            max_completion_tokens=128,
        )
        print(completion.choices[0].message.content)
        verified = await inference_client.verify_response(completion.id)
        print(verified.signature_kind)
```

The client verifies Gateway and model attestations before sending Chat. E2EE
uses the verified model key; setting `e2ee=False` disables field encryption but keeps
attestation verification. `signing_algo` defaults to `'ed25519'` and also accepts
`'ecdsa'`. The selected algorithm applies to evidence, encryption, routing, and
response signatures. ECDSA uses the legacy AES-GCM protocol and omits
`X-Encryption-Version: 2`, which selects the Ed25519 XChaCha20-Poly1305 protocol.

Successful attestation checks are reused for 60 minutes per model.
Set `attestation_cache_time_to_live_ms=0` to check every request.
`response_cache_time_to_live_ms` separately controls how long exact response
bytes remain available after completion; its default is also 60 minutes.

Gateway TLS identity is checked by default, and subsequent evidence, Chat, and
signature requests are pinned to the verified SPKI. When connecting through an
aggregator that terminates TLS, use
`GatewayVerificationOptions(include_spki_fingerprint=False)`; that verifies the
Gateway evidence without claiming the aggregator's TLS identity is the Gateway's.

The client delivers decrypted content before response-signature verification.
Call `verify_response()` after fully consuming a stream:

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

async with InferenceClient(api_key) as inference_client:
    openai_client = AsyncOpenAI(
        api_key=api_key,
        base_url='https://cloud-api.near.ai/v1/',
        http_client=inference_client.http_client,
    )
    completion = await openai_client.chat.completions.create(
        model='z-ai/glm-5.3-flash',
        messages=[{'role': 'user', 'content': 'Hello'}],
    )
    verified = await inference_client.verify_response(completion.id)
```

Use one reusable client for concurrent requests; each response is retained under
its completion ID. `InferenceClient` owns and closes the shared HTTP transport.
Only Chat Completions are supported by this transport, not the Responses API.

### Use OHTTP

Set `ohttp=True` to encapsulate Chat HTTP requests and responses to the Gateway:

```python
async with InferenceClient(api_key, ohttp=True) as inference_client:
    completion = await inference_client.chat.completions.create(
        model='z-ai/glm-5.3-flash',
        messages=[{'role': 'user', 'content': 'Hello'}],
    )
    print(completion.choices[0].message.content)
    verified = await inference_client.verify_response(completion.id)
```

OHTTP is disabled by default and requires `signing_algo='ed25519'` (the default).
The client verifies the advertised OHTTP configuration against the attested
Gateway signer. Missing or invalid OHTTP evidence prevents Chat from being sent.
The authenticated configuration is reused with the attestation cache.

`e2ee` is independent and remains enabled by default: OHTTP protects the HTTP
exchange to the Gateway, while field-level E2EE encrypts supported Chat fields
to the model. Setting `e2ee=False` keeps OHTTP and deployment verification.

JSON, streaming, and external `AsyncOpenAI` calls use the same interfaces.
`verify_response()` checks the inner request and response bodies before E2EE
decryption, not the outer OHTTP ciphertext. Gateway TLS pinning remains enabled.

Only Chat uses OHTTP. Attestation and signature requests keep their normal HTTP
paths. The configured endpoint or proxy must serve `/ohttp` at its origin.
Authorization and explicitly configured custom headers are also sent on the
outer request for authentication; OHTTP does not hide them or the client's
network address from that endpoint.

## Standalone workflow

Create `client = AttestationClient(api_key)` once. It retrieves Gateway evidence
and signatures; the application sends Chat and retains the exact bytes.

## Verification lifecycle

| Stage | SDK calls | What a successful result establishes |
| --- | --- | --- |
| 1. Verify deployments | `fetch_gateway_attestation` → `verify_gateway_attestation`; `fetch_model_attestations` → `verify_model_attestation` | The Gateway deployment and every returned target-model deployment satisfy your evidence and policy checks. |
| 2. Send a completion | Optional `prepare_e2ee_chat_request` | Your application sends Chat and retains the completion ID and exact encrypted request and response bytes. |
| 3. Verify the response signature | `fetch_completion_signature` → verifier selected by `signature.kind` | The selected model or Gateway signer signed those exact bytes. |

Stage 1 is useful before inference: it lets an application reject a deployment
that does not meet its TCB, measurement, GPU, or Gateway-TLS requirements.
Each fetch is a fresh observation, so the application decides when to refresh
that evidence.

## 1. Verify Gateway and model deployments

Verify both deployments before sending the completion. Choose the signing
algorithm your application expects; this example uses ECDSA for all three
requests. Pass the same explicit algorithm to both attestation fetches and the
completion-signature fetch: the Gateway's report and signature endpoints have
different defaults.

```python
from nearai_inference_sdk import (
    AttestationClient,
    verify_gateway_attestation,
    verify_model_attestation,
)

MODEL = 'z-ai/glm-5.3-flash'
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
    if not fetched_model.attestations:
        raise RuntimeError('Gateway returned no model attestations')

    verified_models = []
    for attestation in fetched_model.attestations:
        verified_models.append(
            await verify_model_attestation(
                attestation,
                fetched_model.client_binding,
            )
        )
    return verified_gateway, tuple(verified_models)
```

`fetch_gateway_attestation()` and `fetch_model_attestations()` target the same
Gateway report endpoint, but ask for evidence with different client bindings:

- Gateway evidence requests an SPKI fingerprint by default. The Python SDK
  captures the peer fingerprint from that same HTTPS evidence request, and
  `verify_gateway_attestation` checks that the peer, quote, signer, and nonce
  agree.
- Model evidence requests no TLS fingerprint. The client connects to the
  Gateway rather than directly to a model CVM, so model verification checks the
  signer and nonce binding without making a client-to-model TLS claim.

The fetch helpers generate fresh nonces and reject a response whose echoed
nonce does not match. `fetch_model_attestations()` preserves every returned
model record. This deployment-first workflow rejects an empty collection and
verifies every returned record before inference. `verify_*_attestation` then
verifies the quote, measurements, deployment configuration, and policy.

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

### Optional image build provenance

`fetch_image_provenance` retrieves a digest's GitHub attestation bundles.
`verify_image_provenance` verifies them against Sigstore's production trust root,
matches the signed artifact digest, and checks your expected repository and
workflow. The statement's source commit must match the verified certificate's
source commit, including when no commit pin is supplied. Set `ref` or `commit` to
restrict the accepted build further.

`verify_deployment_image_provenance` selects configured image repositories from
the measured app-compose JSON's `docker_compose_file` YAML. Every configured
repository must occur, and all matching service images must be digest-pinned.
Unrelated literal images are ignored; image references containing `$` are rejected.
Selection completes before any GitHub requests. The application supplies its
trusted image repositories and build policies:

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

The certificate's source repository, ref, and commit must still match the signed
build provenance.

The helpers are asynchronous. The deployment helper reports selection, request,
and verification failures as `VerificationError`; wrapped request failures retain
their retryability. Direct `fetch_image_provenance` failures raise `ApiError`.
Multiple bundles are tried until one satisfies all checks. An optional GitHub
token can be passed to either retrieval helper; do not use a Gateway API key for GitHub.

This proves the selected digest's build provenance. It does not approve the code,
rebuild the image, resolve compose-variable overrides, inspect compose-manager,
or prove which containers are currently running.

## 2. Send the completion and retain exact bytes

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

After verifying the models, select a public key from a verified result before
Chat. `find_model_attestation_for_signature` is used later, when the response
signature is available; it is not the encryption-key selector.

```python
import httpx
from nearai_inference_sdk import E2eeModelKey, prepare_e2ee_chat_request

model = next(item for item in verified_models if item.signing_public_key is not None)
model_key = E2eeModelKey(
    signing_algo=model.signer.signing_algo,
    public_key=model.signing_public_key,
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
Send it using `httpx.AsyncClient`; when Gateway TLS verification is enabled, use
`create_pinned_tls_client(verified_gateway.tls_binding.spki_fingerprint)` instead.
Pass the response to `await prepared.decrypt_response(response)` for JSON or SSE
decryption. Retain the original encrypted response bytes separately for step 3.
Each prepared request owns a fresh response-decryption key.

See [`examples/example-py/bare.py`](../../examples/example-py/bare.py) for the
complete streaming and non-streaming flow, including byte capture and TLS pinning.

## 3. Verify the returned completion signature

Fetch the signature after the completion has reached its terminal state. A
provider signature selects exactly one verified model result from stage 1; a
Gateway signature uses the verified Gateway result.

```python
from nearai_inference_sdk import (
    find_model_attestation_for_signature,
    verify_gateway_response,
    verify_model_response,
)

# completion_id, request_body, and response_body came from your completion
# request. verified_gateway and verified_models came from stage 1.
signature = await client.fetch_completion_signature(
    completion_id,
    signing_algo=SIGNING_ALGO,
)

if signature.kind == 'provider_tee':
    verified_model = find_model_attestation_for_signature(
        verified_models,
        signature,
    )
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

The Gateway provides two signature kinds. They are different response signatures,
not two top-level deployment workflows:

| `signature.kind` | Call | A successful result establishes | It does not establish |
| --- | --- | --- | --- |
| `provider_tee` | `verify_model_response` | A verified model-serving TEE signer signed the exact request and response bytes. | Which Gateway deployment or TLS endpoint returned them. |
| `gateway` | `verify_gateway_response` | A verified Gateway signer signed the exact client-visible request and response bytes. | That an attested model executed or generated them. |

The Gateway can rewrite a response before returning it, for example while
normalizing a stream for OpenAI compatibility. A provider signature over the
upstream bytes cannot verify rewritten bytes, so the Gateway may return a
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
presented as proof that they served the same inference. [cloud-api#986](https://github.com/nearai/cloud-api/issues/986)
tracks the missing chain: preserving a provider signature and adding a Gateway
receipt that binds the upstream and final response hashes for the same
inference.

## Set policy and trust roots

The default policy accepts `UpToDate` and `OutOfDate` TCB statuses. GPU evidence
is verified when present; require it when your application needs it:

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

for attestation in fetched_model.attestations:
    await verify_model_attestation(
        attestation,
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
needs to restrict Gateway TCB statuses. `verifiers.tdx_quote` replaces the built-in
Intel DCAP quote verifier. The default NVIDIA verifier submits evidence to NRAS,
then verifies the overall JWT's ES384 signature against NVIDIA's JWKS, issuer,
expiration, not-before and issued-at times, and signed `eat_nonce`. The overall
verdict must be `true`; detached per-device claims are not consumed. See
[NVIDIA's claims reference](https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/gpu_claims.html).
Set `verifiers.gpu_evidence` to use different trust roots or another verification
service. Every verifier callback must return only for evidence it accepts.

## Configure attestation service URLs

The built-in verifiers use Intel's official PCS endpoint and NVIDIA's official
NRAS and JWKS endpoints. To use proxies with the same verification checks,
create verifier callbacks with the desired URLs:

```python
from nearai_inference_sdk import (
    ModelAttestationVerifiers,
    create_tdx_quote_verifier,
    create_gpu_evidence_verifier,
)

verifiers = ModelAttestationVerifiers(
    tdx_quote=create_tdx_quote_verifier(
        pccs_url='https://attestation.example.com',
    ),
    gpu_evidence=create_gpu_evidence_verifier(
        nras_url='https://attestation.example.com/v3/attest/gpu',
        jwks_url='https://attestation.example.com/.well-known/jwks.json',
    ),
)
```

Pass `verifiers` to `verify_model_attestation`; Gateway verification accepts the
same quote callback through `AttestationVerifiers(tdx_quote=...)`. Each URL is
optional and defaults to its official endpoint. Configuration belongs to the
returned callback and does not change other verifiers.

The PCCS proxy must serve compatible collateral bodies and issuer-chain headers
under both `/sgx/certification/v4/...` and `/tdx/certification/v4/...`;
`dcap-qvl` constructs these paths. Provide the PCCS-compatible, hex-encoded root
CA CRL at `/sgx/certification/v4/rootcacrl` to avoid its fallback to the root
certificate's CRL distribution URL. Quote signatures, certificate chains, and
collateral are still verified locally.

The NVIDIA adapter submits the unchanged evidence JSON to `nras_url` and obtains
signing keys from `jwks_url`. A custom JWKS URL selects a trust source: use only
a trusted proxy. The fixed NVIDIA issuer check does not authenticate arbitrary
JWKS sources. ES384 signatures, issuer, timestamps, signed nonce, and the boolean
verdict remain checked.

`verify_model_attestation` checks the payload nonce against the matching client
nonce before invoking any NVIDIA callback. The factory's callback also requires
a 32-byte hexadecimal payload nonce and checks it against the signed JWT nonce.
When calling that callback directly, the application must additionally bind the
payload nonce to its own fresh request nonce.

## Handle retrieval and verification errors

For integrated Chat, OpenAI wraps transport errors in `APIConnectionError`;
inspect `error.__cause__` for the original SDK failure. `InferenceClient.send()`
and `verify_response()` expose SDK errors directly. A failed preflight sends no
Chat request, while a failed response check occurs after content was received.

`client.fetch_completion_signature()` returns one signature or raises a
structured error. A 2xx unavailable envelope raises `ApiError` with
`api.completion_signature_unavailable`; its details contain the service's
`providerErrorCode` and `providerMessage`.

An HTTP 404 raises `api.http_status` and remains retryable. It means the Gateway
has no stored signature for that ID at that time. Retry only when the
application has reason to expect a later signature, such as before the
completion has reached its terminal state.

`AttestationClient` methods and evidence selection raise `ApiError` for
request, HTTP, response-format, nonce, unavailable-signature,
candidate-selection, or helper-input failures. Explicit verification functions
raise `VerificationError` for local input, cryptographic, policy, and binding
failures. Handle each stage separately: client and selection handlers catch
`ApiError`, while explicit verification handlers catch `VerificationError`.

| Field | Meaning |
| --- | --- |
| `error.failure.code` | Stable code for an application to branch on. |
| `error.failure.details` (when present) | Code-specific diagnostic context. Do not parse `error.message`. |
| `error.retryable` | A new attempt at the failed external operation may succeed. It does not mean that re-verifying the same evidence will succeed or that an inference should be replayed. |

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
