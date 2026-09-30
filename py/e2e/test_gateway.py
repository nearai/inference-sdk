"""Live Gateway tests. Run explicitly with uv run pytest e2e."""

import asyncio
import json
import os
import re

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
@pytest.mark.parametrize('stream', [False, True], ids=['json', 'sse'])
async def test_gateway_chat_receipt(signing_algo: SigningAlgo, stream: bool) -> None:
    base_url = required_env('NEARAI_E2E_BASE_URL').rstrip('/') + '/'
    api_key = required_env('NEARAI_E2E_API_KEY')
    model = os.environ.get('NEARAI_E2E_MODEL') or 'z-ai/glm-5.3-flash'
    client = AttestationClient(api_key, base_url=base_url)

    async with asyncio.timeout(180):
        fetched_gateway = await client.fetch_gateway_attestation(
            signing_algo=signing_algo,
        )
        gateway = await verify_gateway_attestation(
            fetched_gateway.attestation,
            fetched_gateway.client_binding,
        )
        assert gateway.tls_binding.kind == 'attested'

        fetched_models = await client.fetch_model_attestations(
            model,
            signing_algo=signing_algo,
        )
        assert fetched_models.attestations, 'Expected NEAR model evidence'
        models = []
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
                'messages': [
                    {'role': 'user', 'content': 'Reply with the single word OK.'}
                ],
                'max_completion_tokens': 128,
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
        signature = await fetch_signature_with_retry(
            client, completion_id, signing_algo
        )
        assert signature.signer.signing_algo == signing_algo
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
        assert re.search(
            r'\bOK\b', completion['choices'][0]['message']['content'], re.IGNORECASE
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
    content = ''.join(
        choice.get('delta', {}).get('content') or ''
        for chunk in chunks
        for choice in chunk.get('choices', [])
    )
    assert re.search(r'\bOK\b', content, re.IGNORECASE)
    return completion_id


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f'{name} is required for live E2E tests')
    return value
