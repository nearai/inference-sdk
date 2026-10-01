# Python guide

Start with the [quick start](../README.md#quick-start) for a non-streaming Chat
request. The examples here use the same `NEARAI_API_KEY` environment variable
and Python 3.12+. Save a complete example as `example.py` and run
`python example.py`.

- [Stream a response](#stream-an-e2ee-completion)
- [Use the OpenAI SDK](#use-the-official-openai-sdk)
- [Verification and caching](#cache-deployment-verification)
- [Encryption](#e2ee-scope-and-response-handling)
- [Policies and image provenance](#set-verification-policy)
- [Proxy setup](#connect-through-an-application-proxy)
- [Manual verification](#verify-gateway-requests-manually)
- [Direct endpoints](#direct-model-endpoints)
- [Errors](#handle-errors)

For option and result fields, see the [API reference](./api-reference.md).

## What verification proves

Before sending Chat, the client verifies the Gateway and every returned model
attestation for supported NEAR TEE models. Those checks authenticate the signing
keys, Intel TDX quotes, nonces, and measured deployment configuration. Model
checks also verify NVIDIA GPU evidence when present.

Models without supported model attestation use **Incognito** mode: only the
Gateway is verified. E2EE and model deployment policies require model evidence,
so they reject Incognito models. A failed model check never falls back to
Gateway-only verification.

Attestation checks a deployment. A response signature connects the exact
request and response bytes to a verified signer:

| Signature kind | What response verification proves |
| --- | --- |
| `provider_tee` | A verified model TEE signer signed the request and response bytes. |
| `gateway` | A verified Gateway signer signed the client-visible bytes. This does not prove model execution. |

The Gateway may sign a response after rewriting it, such as normalizing streaming
usage fields. In that case the original model signature cannot verify the
rewritten bytes. The client selects the response verifier from the returned
signature kind. Verifying both deployments does not add a missing model signature
to a Gateway-signed response ([tracking issue](https://github.com/nearai/cloud-api/issues/986)).

## Stream an E2EE completion

Consume the full stream, then verify it using the completion ID from its chunks.
This example displays tokens as they arrive, before signature verification.
Buffer them instead if your application must display only verified output.

```python
import asyncio
import os

from nearai_inference_sdk import InferenceClient


async def main() -> None:
    async with InferenceClient(
        os.environ['NEARAI_API_KEY'],
        e2ee=True,
    ) as client:
        stream = await client.chat.completions.create(
            model='z-ai/glm-5.3-flash',
            messages=[{'role': 'user', 'content': 'Write a short greeting.'}],
            stream=True,
        )

        completion_id = None
        async for chunk in stream:
            completion_id = chunk.id
            if chunk.choices:
                print(chunk.choices[0].delta.content or '', end='', flush=True)
        print()

        if not completion_id:
            raise RuntimeError('Stream returned no completion ID')
        verified = await client.verify_response(completion_id)
        print(f'Verified {verified.signature_kind} response')


if __name__ == '__main__':
    asyncio.run(main())
```

`verify_response()` uses the request and response bytes captured by the client,
including encrypted bytes when E2EE is enabled. It does not send Chat again.

## Use the official OpenAI SDK

The SDK includes the `openai` dependency. Pass the inference client's HTTP
adapter to `AsyncOpenAI`, and verify through the same inference client:

```python
import asyncio
import os

from openai import AsyncOpenAI
from nearai_inference_sdk import InferenceClient


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    base_url = 'https://cloud-api.near.ai/v1'
    async with InferenceClient(api_key, base_url=base_url, e2ee=True) as client:
        async with AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=client.http_client,
        ) as openai:
            completion = await openai.chat.completions.create(
                model='z-ai/glm-5.3-flash',
                messages=[{'role': 'user', 'content': 'Hello!'}],
            )
        await client.verify_response(completion.id)
        print(completion.choices[0].message.content or '')


if __name__ == '__main__':
    asyncio.run(main())
```

The adapter supports Chat Completions, including streaming, not the Responses
API. Configure authentication on `InferenceClient`; its credentials take
precedence over those supplied by the OpenAI client. Keep the inference client
open until response verification finishes. Closing the external OpenAI client
does not close the inference client's connections or discard its response records.

## Cache deployment verification

Reuse a client across requests. Successful deployment checks are cached per
model for 60 minutes. To verify while a user selects a model, put this call
before Chat in the quick start:

```python
attestations = await client.verify('z-ai/glm-5.3-flash')
print('Gateway TCB:', attestations.gateway.tcb_status)
for model in attestations.models:
    print('Model TCB:', model.tcb_status)
```

This sends no Chat request. It returns the verified Gateway, model reports, and
`verified_at` in Unix milliseconds. Incognito models have an empty `models` tuple.
Cache hits preserve the result and its timestamp; concurrent calls for the same
model share in-flight verification. Response signatures still require a separate
`verify_response(id)` call after Chat.

To change cache durations, construct the client as below inside `main()`.
Use `async with client:` for the Chat calls:

```python
client = InferenceClient(
    os.environ['NEARAI_API_KEY'],
    e2ee=True,
    attestation_cache_time_to_live_ms=15 * 60 * 1000,
    response_cache_time_to_live_ms=5 * 60 * 1000,
)
```

Set `attestation_cache_time_to_live_ms=0` to verify before every request, even
after an explicit `verify()`. Cached checks do not detect deployment changes
until they expire.

The response cache is separate. It retains complete request and response bodies
in memory, and its TTL starts when the response finishes. Call
`verify_response(id)` before expiry. Unknown or expired IDs fail with
`api.completion_not_found`.

## E2EE scope and response handling

Set `e2ee=True` to encrypt supported Chat fields to a verified model key.
Leave it off to send plaintext over HTTPS while keeping deployment and response
verification available.

E2EE covers message content, including rich-content arrays, reasoning fields,
audio data, and supported tool/function fields. Other fields, URL parameters,
and HTTP headers are not field-encrypted. Decryption checks the encrypted
message's authentication tag; response-signature verification remains a
separate `verify_response()` call.

`signing_algo` selects one algorithm for attestation, model-key routing,
encryption, and response signatures. It defaults to `'ed25519'`.
Add `signing_algo='ecdsa'` to the client constructor to use ECDSA.

Ed25519 encryption uses XChaCha20-Poly1305 and `X-Encryption-Version: 2`.
ECDSA uses secp256k1 ECDH with AES-GCM and omits that header because version 2
selects the Ed25519 protocol. Both modes enable `X-Encrypt-All-Fields` for the
supported fields listed above.

### Use OHTTP

Add `ohttp=True` to the client constructor to encrypt the Chat HTTP exchange
to the Gateway. Keep the default Ed25519 algorithm; OHTTP does not support ECDSA.
Chat, streaming, and response-verification calls stay the same.

OHTTP and model E2EE protect different parts of a request. They can be enabled
together, or OHTTP can be used alone with Incognito models. The endpoint must
serve `/ohttp` at its origin and provide a signed key configuration, which the
client verifies before use.

Metadata, attestation, and signature lookups do not use OHTTP. Authorization and
configured custom headers are also sent on the outer request. OHTTP does not
hide them or the client's network address from that endpoint.

## Set verification policy

The default policy accepts `UpToDate` and `OutOfDate` Intel TCB statuses and
verifies GPU evidence when present. This client configuration requires an
up-to-date platform and GPU evidence. Add the imports, then use this client
inside `main()` with `async with client:`:

```python
from nearai_inference_sdk import (
    AttestationPolicy,
    GatewayVerificationOptions,
    ModelAttestationPolicy,
    ModelVerificationOptions,
)

client = InferenceClient(
    os.environ['NEARAI_API_KEY'],
    e2ee=True,
    gateway_verification=GatewayVerificationOptions(
        policy=AttestationPolicy(accepted_tcb_statuses=('UpToDate',)),
    ),
    model_verification=ModelVerificationOptions(
        policy=ModelAttestationPolicy(
            accepted_tcb_statuses=('UpToDate',),
            gpu_evidence='required',
        ),
    ),
)
```

These checks authenticate measurements but do not approve a software release.
Use `deployment_policy` to compare each model's authenticated measurements
with your own allowlist. The callback receives the requested model and its
measured deployment; raise to reject it. There is no built-in release allowlist.

### Optional image build provenance

A deployment callback can also check measured container images against their
published GitHub build proofs. This configuration checks one Gateway image.
Add the imports and callback, then construct this client inside `main()` and
use it with `async with client:`:

```python
from nearai_inference_sdk import (
    AttestationVerifiers,
    GatewayVerificationOptions,
    ImageProvenancePolicy,
    MeasuredDeployment,
    verify_deployment_image_provenance,
)

IMAGE_POLICIES = {
    'nearaidev/cloud-api': ImageProvenancePolicy(
        repository='nearai/cloud-api',
        workflow='.github/workflows/build.yml',
    ),
}


async def check_images(deployment: MeasuredDeployment) -> None:
    await verify_deployment_image_provenance(deployment.app_compose, IMAGE_POLICIES)


client = InferenceClient(
    os.environ['NEARAI_API_KEY'],
    e2ee=True,
    gateway_verification=GatewayVerificationOptions(
        verifiers=AttestationVerifiers(deployment=check_images),
    ),
)
```

The callback runs after the configuration is authenticated by attestation.
Every image repository in the policy must be present and digest-pinned.
Unlisted images are not checked. A valid build proof establishes the repository,
workflow, and source commit; add an approved `commit` to restrict accepted
versions. This is not proof of the containers currently running after boot.

The [client example](../../examples/example-py/gateway/client.py) checks four
Gateway images. Those policies are example configuration, not SDK defaults or
model-image policies. For reusable workflows and other policy fields, see
[image build provenance](./api-reference.md#image-build-provenance).

## Connect through an application proxy

Keep the NEAR API key on your backend. Forward metadata, attestation, Chat, and
signature requests without rewriting bodies or dropping model-routing and
encryption headers.

Use your application's token in `headers` instead of a NEAR API key. If the
proxy terminates TLS, disable attested Gateway TLS binding: the proxy's
certificate is not the attested Gateway's. Normal HTTPS validation still applies.
This factory uses a placeholder URL for your backend:

```python
from nearai_inference_sdk import GatewayVerificationOptions, InferenceClient


def create_proxy_client(application_token: str) -> InferenceClient:
    return InferenceClient(
        base_url='https://api.example.com/v1',
        headers={'Authorization': f'Bearer {application_token}'},
        e2ee=True,
        gateway_verification=GatewayVerificationOptions(
            include_spki_fingerprint=False,
        ),
    )
```

Your application passes its own login token to this factory and manages the
returned client with `async with`, as in the quick start.

The proxy must forward `/v1/model/{model}`, `/v1/attestation/report`,
`/v1/chat/completions`, and `/v1/signature/{id}`.
Preserve URL-encoded IDs. With OHTTP, also forward `/ohttp`.

### Configure attestation service URLs

The quote verifier uses Intel's collateral service by default. NVIDIA
verification uses NRAS and NVIDIA's JWKS. To use trusted proxies, add these
imports, then construct this client inside `main()` and use it with
`async with client:`:

```python
from nearai_inference_sdk import (
    AttestationVerifiers,
    GatewayVerificationOptions,
    ModelAttestationVerifiers,
    ModelVerificationOptions,
    create_gpu_evidence_verifier,
    create_tdx_quote_verifier,
)

tdx_quote = create_tdx_quote_verifier(
    pccs_url='https://attestation.example.com',
)
gpu_evidence = create_gpu_evidence_verifier(
    nras_url='https://attestation.example.com/v3/attest/gpu',
    jwks_url='https://attestation.example.com/.well-known/jwks.json',
)
client = InferenceClient(
    os.environ['NEARAI_API_KEY'],
    e2ee=True,
    gateway_verification=GatewayVerificationOptions(
        verifiers=AttestationVerifiers(tdx_quote=tdx_quote),
    ),
    model_verification=ModelVerificationOptions(
        verifiers=ModelAttestationVerifiers(
            tdx_quote=tdx_quote,
            gpu_evidence=gpu_evidence,
        ),
    ),
)
```

A PCCS proxy must preserve collateral bodies and issuer-chain headers for the
SGX and TDX v4 paths. Serve the hex-encoded root CRL at
`/sgx/certification/v4/rootcacrl` to avoid a direct CRL fallback.

Changing URLs does not disable cryptographic checks. A custom JWKS endpoint
does select the trusted source of NVIDIA signing keys, so use only a trusted
proxy. An issuer check alone cannot authenticate keys from an arbitrary server.

## Verify Gateway requests manually

Use `AttestationClient` and standalone verifiers when you need to inspect
evidence or control when checks run. This complete example audits deployments
without sending Chat:

```python
import asyncio
import os

from nearai_inference_sdk import (
    AttestationClient,
    verify_gateway_attestation,
    verify_model_attestation,
)


async def main() -> None:
    client = AttestationClient(os.environ['NEARAI_API_KEY'])
    fetched_gateway = await client.fetch_gateway_attestation(signing_algo='ed25519')
    gateway = await verify_gateway_attestation(
        fetched_gateway.attestation,
        fetched_gateway.client_binding,
    )
    print(f'Gateway TCB: {gateway.tcb_status}')

    fetched_models = await client.fetch_model_attestations(
        'z-ai/glm-5.3-flash',
        signing_algo='ed25519',
    )
    if not fetched_models.attestations:
        raise RuntimeError('No model attestations returned')
    for attestation in fetched_models.attestations:
        model = await verify_model_attestation(
            attestation,
            fetched_models.client_binding,
        )
        print(f'Model TCB: {model.tcb_status}; GPU: {model.gpu_evidence}')


if __name__ == '__main__':
    asyncio.run(main())
```

Fetch generates a fresh nonce and checks the echoed value. Verification
authenticates that nonce in the quote along with the signer and measurements.
Gateway evidence also binds the observed TLS key. Model evidence retrieved
through the Gateway has no client-to-model TLS binding.

To verify a Chat response manually, follow the complete
[bare example](../../examples/example-py/gateway/bare.py). It verifies
deployments first, encrypts and sends Chat, saves the exact encrypted request
and response bytes, decrypts the response, and verifies its signature. It
includes both JSON and streaming calls.

Keep the same explicit signing algorithm for attestation and signature fetches;
the service endpoints have different defaults. Verify every fetched model
report before Chat. Later, `find_model_attestation_for_signature` selects the
verified model matching a `provider_tee` signature. A `gateway` signature
uses the verified Gateway result instead.

### Encrypt a raw Chat request

For application-owned HTTP requests, `prepare_e2ee_chat_request` takes an
`httpx.Request` and an already verified model public key. It returns an
encrypted request and its paired JSON/SSE response decryptor. It does not verify
the attestation or send the request.

The bare example shows key selection and byte capture. Response verification
uses the encrypted bytes, not decrypted or reserialized JSON.
`create_pinned_tls_client` can bind application-owned requests to the
previously verified Gateway SPKI.

## Direct model endpoints

`DirectInferenceClient.verify(model)` returns every verified direct report, the
serving entry, TLS binding, and `verified_at`. It has no Gateway result.

Direct clients are experimental and not recommended for production. They verify
model evidence without Gateway attestation or catalog lookup.

`DirectInferenceClient` takes the model endpoint's `base_url` and defaults
to E2EE enabled. Chat, streaming, OpenAI integration, and response verification
use the same interfaces as the Gateway client.
See the runnable [direct client](../../examples/example-py/direct/client.py)
and [manual verification](../../examples/example-py/direct/bare.py) examples.

Direct clients currently request no TLS fingerprint and perform no attested
TLS pinning. Standard HTTPS validation remains enabled. Reports may omit other
serving instances, and a signature lookup may return 404 when it reaches a
different instance ([endpoint limitations](https://github.com/nearai/cloud-api/issues/1087)).
Every report returned is still verified.

## Handle errors

Deployment verification failures stop Chat before it is sent. Response
verification failures happen after receiving content.

The built-in Chat interface and external OpenAI clients preserve OpenAI's error
behavior. A transport failure is wrapped in `APIConnectionError`; its
`__cause__` contains the SDK error. `client.send()` and
`client.verify_response()` expose SDK errors directly.

Add these imports and replace the verification and output lines in the quick start:

```python
from nearai_inference_sdk import ApiError, VerificationError

try:
    await client.verify_response(completion.id)
    print(completion.choices[0].message.content or '')
except (ApiError, VerificationError) as error:
    print(error.failure.code, error.failure.details)
    raise
```

Use the structured failure code for application decisions. `retryable` means
a failed external operation may succeed on another attempt, not that Chat
should be replayed. An expired response record cannot be recovered by retrying
verification.

In a manual flow, fetching and selecting evidence raise `ApiError`;
verification functions raise `VerificationError`.
