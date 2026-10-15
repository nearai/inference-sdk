"""Live Gateway tests. Run explicitly with uv run pytest e2e."""

import asyncio
import json
import os
from collections.abc import Awaitable, Callable

import pytest
from openai import AsyncOpenAI
from openai.resources.chat import AsyncChat

from e2e.retry import retry_rate_limit
from nearai_inference_sdk import (
    ApiError,
    AttestationClient,
    InferenceClient,
    ModelAttestationPolicy,
    ModelVerificationOptions,
    SigningAlgo,
    VerificationError,
    VerifiedCompletionResult,
    create_pinned_tls_client,
    find_model_attestation_for_signature,
    verify_gateway_attestation,
    verify_gateway_response,
    verify_model_attestation,
    verify_model_response,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('e2ee', 'signing_algo', 'ohttp'),
    [
        (False, 'ed25519', False),
        (True, 'ed25519', False),
        (True, 'ecdsa', False),
        (True, 'ed25519', True),
    ],
    ids=['unencrypted', 'ed25519-e2ee', 'ecdsa-e2ee', 'ohttp-e2ee'],
)
async def test_inference_client_verifies_json_and_streams(
    e2ee: bool, signing_algo: SigningAlgo, ohttp: bool
) -> None:
    model = selected_models('near')[0]
    async with (
        asyncio.timeout(180),
        InferenceClient(
            required_env('NEARAI_API_KEY'),
            base_url=required_env('NEARAI_BASE_URL'),
            signing_algo=signing_algo,
            e2ee=e2ee,
            ohttp=ohttp,
            model_verification=ModelVerificationOptions(
                policy=ModelAttestationPolicy(gpu_evidence='required'),
            ),
        ) as inference_client,
    ):
        # Explicit preflight shares its verified session with both Chat calls.
        await inference_client.verify(model)
        for stream in (False, True):
            await verify_client_chat(
                inference_client, inference_client.chat, model, signing_algo, stream
            )


@pytest.mark.asyncio
@pytest.mark.parametrize('provider', ['chutes', 'external'])
async def test_inference_client_verifies_gateway_only_receipts(provider: str) -> None:
    for model in selected_models(provider):
        async with (
            asyncio.timeout(180),
            InferenceClient(
                required_env('NEARAI_API_KEY'),
                base_url=required_env('NEARAI_BASE_URL'),
                e2ee=False,
            ) as inference_client,
        ):
            await inference_client.verify(model)
            # Chutes streaming is separately provider-gated; use JSON only.
            streams = (False,) if provider == 'chutes' else (False, True)
            for stream in streams:
                verified = await verify_client_chat(
                    inference_client, inference_client.chat, model, 'ed25519', stream
                )
                assert verified.signature_kind == 'gateway'


@pytest.mark.asyncio
async def test_openai_sdk_uses_the_verified_http_client() -> None:
    api_key = required_env('NEARAI_API_KEY')
    base_url = required_env('NEARAI_BASE_URL')
    model = selected_models('near')[0]
    async with (
        asyncio.timeout(180),
        InferenceClient(
            api_key,
            base_url=base_url,
            e2ee=True,
            model_verification=ModelVerificationOptions(
                policy=ModelAttestationPolicy(gpu_evidence='required'),
            ),
        ) as inference_client,
        AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=inference_client.http_client,
            max_retries=0,
        ) as openai_client,
    ):
        # The first Chat performs preflight through the supplied transport.
        for stream in (False, True):
            await verify_client_chat(
                inference_client, openai_client.chat, model, 'ed25519', stream
            )


async def verify_client_chat(
    inference_client: InferenceClient,
    chat: AsyncChat,
    model: str,
    signing_algo: SigningAlgo,
    stream: bool,
) -> VerifiedCompletionResult:
    response = await retry_rate_limit(
        lambda: chat.completions.create(
            model=model,
            messages=[{'role': 'user', 'content': 'Reply with the single word OK.'}],
            max_completion_tokens=1024,
            stream=stream,
        )
    )
    if stream:
        completion_id = None
        content = ''
        finish_reason = None
        async with response:
            async for chunk in response:
                if completion_id is not None:
                    assert chunk.id == completion_id
                completion_id = chunk.id
                for choice in chunk.choices:
                    content += choice.delta.content or ''
                    if choice.finish_reason is not None:
                        finish_reason = choice.finish_reason
        assert completion_id, 'SSE must contain a completion ID'
        assert finish_reason == 'stop', 'SSE must complete without truncation'
        assert content.strip(), 'Expected non-empty Chat content'
    else:
        completion_id = response.id
        assert completion_id
        assert response.choices[0].finish_reason == 'stop'
        assert (response.choices[0].message.content or '').strip(), (
            'Expected non-empty Chat content'
        )

    # Verify retained wire bytes only after the response has been consumed.
    verified = await retry_receipt(
        lambda: inference_client.verify_response(completion_id)
    )
    assert verified.id == completion_id
    assert verified.signature.signer.signing_algo == signing_algo
    return verified


@pytest.mark.asyncio
@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
@pytest.mark.parametrize(
    ('provider', 'stream'),
    [
        ('near', False),
        ('near', True),
        ('chutes', False),
        ('external', False),
        ('external', True),
    ],
    ids=['near-json', 'near-sse', 'chutes-json', 'external-json', 'external-sse'],
)
async def test_gateway_chat_receipt(
    signing_algo: SigningAlgo, stream: bool, provider: str
) -> None:
    for model in selected_models(provider):
        print(f'{provider}: {model}, {signing_algo}, stream={stream}')
        async with asyncio.timeout(180):
            await verify_chat(model, provider, signing_algo, stream)


async def verify_chat(
    model: str, provider: str, signing_algo: SigningAlgo, stream: bool
) -> None:
    base_url = required_env('NEARAI_BASE_URL').rstrip('/') + '/'
    api_key = required_env('NEARAI_API_KEY')
    client = AttestationClient(api_key, base_url=base_url)

    # Only NEAR model evidence uses this SDK's model verification path.
    fetched_gateway = await client.fetch_gateway_attestation(
        signing_algo=signing_algo,
    )
    gateway = await verify_gateway_attestation(
        fetched_gateway.attestation,
        fetched_gateway.client_binding,
    )
    assert gateway.tls_binding.kind == 'attested'

    models = []
    if provider == 'near':
        fetched_models = await client.fetch_model_attestations(
            model,
            signing_algo=signing_algo,
        )
        assert fetched_models.attestations, 'Expected NEAR model evidence'
        for attestation in fetched_models.attestations:
            verified = await verify_model_attestation(
                attestation,
                fetched_models.client_binding,
                policy=ModelAttestationPolicy(gpu_evidence='required'),
            )
            models.append(verified)

    request_body = json.dumps(
        {
            'model': model,
            'messages': [{'role': 'user', 'content': 'Reply with the single word OK.'}],
            # Reasoning tokens share this budget; leave room for a visible answer.
            'max_completion_tokens': 1024,
            'stream': stream,
        },
        separators=(',', ':'),
    ).encode()
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
        'Accept-Encoding': 'identity',
        'x-no-aliasing': 'true',
    }
    # Bind Chat's TLS peer to the Gateway whose attestation passed verification.
    async with create_pinned_tls_client(
        gateway.tls_binding.spki_fingerprint
    ) as pinned_tls_client:
        response = await retry_rate_limit(
            lambda: pinned_tls_client.post(
                base_url + 'chat/completions', content=request_body, headers=headers
            )
        )
        assert response.status_code == 200, f'Chat returned HTTP {response.status_code}'
        response_body = response.content

    completion_id = read_completion_id(response_body, stream)
    signature = await retry_receipt(
        lambda: client.fetch_completion_signature(
            completion_id, signing_algo=signing_algo
        )
    )
    assert signature.signer.signing_algo == signing_algo
    if provider != 'near':
        assert signature.kind == 'gateway'
    # Keep original wire bytes. Even appended whitespace must invalidate them.
    altered = response_body + b' '
    if signature.kind == 'provider_tee':
        attestation = find_model_attestation_for_signature(models, signature)
        verify_model_response(request_body, response_body, signature, attestation)
        with pytest.raises(VerificationError):
            verify_model_response(request_body, altered, signature, attestation)
    else:
        verify_gateway_response(request_body, response_body, signature, gateway)
        with pytest.raises(VerificationError):
            verify_gateway_response(request_body, altered, signature, gateway)


async def retry_receipt[T](lookup: Callable[[], Awaitable[T]]) -> T:
    # Retry receipt propagation only. Never repeat Chat or cryptographic checks.
    for delay in (0.5, 1, 2, 4):
        try:
            return await lookup()
        except ApiError as error:
            if not error.retryable:
                raise
        await asyncio.sleep(delay)
    return await lookup()


def read_completion_id(response_body: bytes, stream: bool) -> str:
    if not stream:
        completion = json.loads(response_body)
        assert isinstance(completion['id'], str) and completion['id']
        assert completion['choices'][0]['finish_reason'] == 'stop'
        assert completion['choices'][0]['message']['content'].strip(), (
            'Expected non-empty Chat content'
        )
        return completion['id']

    events = [
        line.removeprefix('data:').strip()
        for line in response_body.decode().splitlines()
        if line.startswith('data:')
    ]
    assert events and events[-1] == '[DONE]', 'Expected a complete SSE response'
    chunks = [json.loads(event) for event in events if event != '[DONE]']
    completion_id = chunks[0]['id']
    assert isinstance(completion_id, str) and completion_id
    assert all(chunk['id'] == completion_id for chunk in chunks)
    finish_reasons = [
        choice['finish_reason']
        for chunk in chunks
        for choice in chunk.get('choices', [])
        if choice.get('finish_reason') is not None
    ]
    assert finish_reasons and finish_reasons[-1] == 'stop', (
        'SSE must complete without truncation'
    )
    content = ''.join(
        choice.get('delta', {}).get('content') or ''
        for chunk in chunks
        for choice in chunk.get('choices', [])
    )
    assert content.strip(), 'Expected non-empty Chat content'
    return completion_id


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f'{name} is required for live E2E tests')
    return value


def selected_models(provider: str) -> list[str]:
    selected = json.loads(required_env('NEARAI_E2E_MODELS'))
    models = [model['id'] for model in selected if model['provider'] == provider]
    assert models, f'Expected {provider} models from the catalog'
    return models
