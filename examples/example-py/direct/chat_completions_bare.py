"""Experimental manual direct verification. This example sends plaintext over HTTPS."""

import asyncio
import json
import os

import httpx
from nearai_inference_sdk import (
    DirectAttestationClient,
    VerifiedDirectModelAttestations,
    create_pinned_tls_client,
    verify_direct_model_attestations,
    verify_direct_model_response,
)

from utils.chat_output import RecordingStream, read_stream

BASE_URL = (
    os.environ.get(
        'NEARAI_BASE_URL', 'https://glm-5-3-flash.completions.near.ai/v1/'
    ).rstrip('/')
    + '/'
)
MODEL = os.environ.get('NEARAI_MODEL', 'z-ai/glm-5.3-flash')
SIGNING_ALGO = os.environ.get('NEARAI_SIGNING_ALGO', 'ed25519')


async def send_and_verify(
    client: httpx.AsyncClient,
    attestation_client: DirectAttestationClient,
    verified: VerifiedDirectModelAttestations,
    *,
    stream: bool,
) -> None:
    request = client.build_request(
        'POST',
        BASE_URL + 'chat/completions',
        json={
            'model': MODEL,
            'messages': [{'role': 'user', 'content': 'Reply with the word ok.'}],
            'max_completion_tokens': 1024,
            'stream': stream,
        },
    )
    response = await client.send(request, stream=True)
    recording = RecordingStream(response)
    response = httpx.Response(
        response.status_code,
        headers={'Content-Type': response.headers.get('content-type', '')},
        stream=recording,
        request=request,
    )
    try:
        response.raise_for_status()
        values = (
            await read_stream(response)
            if stream
            else [json.loads(await response.aread())]
        )
        response_body = b''.join(recording.chunks)
    finally:
        await response.aclose()
    completion_id = next((value['id'] for value in values if value.get('id')), None)
    if completion_id is None:
        raise RuntimeError('Stream returned no completion ID')
    text = ''.join(
        choice.get('delta' if stream else 'message', {}).get('content') or ''
        for value in values
        for choice in value.get('choices', [])[:1]
    )
    signature = await attestation_client.fetch_completion_signature(
        completion_id, signing_algo=SIGNING_ALGO
    )
    matching = verify_direct_model_response(
        request.content, response_body, signature, verified.attestations
    )
    print(f'Verified response against {len(matching)} model reports.')
    if not stream:
        print(text)


async def main() -> None:
    api_key = os.environ.get('NEARAI_API_KEY')
    attestation_client = DirectAttestationClient(BASE_URL, api_key=api_key)
    fetched_attestations = await attestation_client.fetch_model_attestations(
        signing_algo=SIGNING_ALGO
    )
    verified = await verify_direct_model_attestations(fetched_attestations)
    print(f'Verified {len(verified.attestations)} model reports.')
    headers = {'Accept-Encoding': 'identity', 'X-No-Aliasing': 'true'}
    if api_key is not None:
        headers['Authorization'] = f'Bearer {api_key}'
    async with create_pinned_tls_client(verified.spki_fingerprints) as client:
        client.headers.update(headers)
        attestation_client = DirectAttestationClient(
            BASE_URL, api_key=api_key, http_client=client
        )
        await send_and_verify(client, attestation_client, verified, stream=False)
        await send_and_verify(client, attestation_client, verified, stream=True)


if __name__ == '__main__':
    asyncio.run(main())
