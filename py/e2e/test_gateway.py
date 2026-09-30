"""Live Gateway tests. Run explicitly with uv run pytest e2e."""

import asyncio
import json
import os

import aiohttp
import pytest

from nearai_inference_sdk import (
    ApiError,
    AttestationClient,
    CompletionSignature,
    ModelAttestationPolicy,
    SigningAlgo,
    VerificationError,
    find_model_attestation_for_signature,
    verify_gateway_attestation,
    verify_gateway_response,
    verify_model_attestation,
    verify_model_response,
)


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
    selected = json.loads(required_env('NEARAI_E2E_MODELS'))
    models = [model['id'] for model in selected if model['provider'] == provider]
    assert models, f'Expected {provider} models from the catalog'
    for model in models:
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
    async with (
        aiohttp.ClientSession(auto_decompress=False) as session,
        session.post(
            base_url + 'chat/completions', data=request_body, headers=headers
        ) as response,
    ):
        assert response.status == 200, f'Chat returned HTTP {response.status}'
        response_body = await response.read()

    completion_id = read_completion_id(response_body, stream)
    signature = await fetch_signature_with_retry(client, completion_id, signing_algo)
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


async def fetch_signature_with_retry(
    client: AttestationClient, completion_id: str, signing_algo: SigningAlgo
) -> CompletionSignature:
    # Retry receipt propagation only. Never repeat Chat or cryptographic checks.
    for delay in (0.5, 1, 2, 4):
        try:
            return await client.fetch_completion_signature(
                completion_id, signing_algo=signing_algo
            )
        except ApiError as error:
            if not error.retryable:
                raise
        await asyncio.sleep(delay)
    return await client.fetch_completion_signature(
        completion_id, signing_algo=signing_algo
    )


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
