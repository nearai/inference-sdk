"""Experimental manual direct verification. This example sends plaintext over HTTPS."""

import asyncio
import codecs
import json
import os

import httpx
from nearai_inference_sdk import (
    DirectAttestationClient,
    VerifiedDirectModelAttestations,
    verify_direct_model_attestations,
    verify_direct_model_response,
)


BASE_URL = 'https://glm-5-3-flash.completions.near.ai/v1/'
MODEL = 'z-ai/glm-5.3-flash'
SIGNING_ALGO = 'ed25519'


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
            'max_completion_tokens': 8,
            'stream': stream,
        },
    )
    response = await client.send(request, stream=True)
    try:
        response.raise_for_status()
        chunks = []
        decoder = codecs.getincrementaldecoder('utf-8')()
        async for chunk in response.aiter_bytes():
            chunks.append(chunk)
            if stream:
                print(decoder.decode(chunk), end='', flush=True)
        response_body = b''.join(chunks)
    finally:
        await response.aclose()
    if stream:
        print(decoder.decode(b'', final=True))
        completion_id = read_stream_id(response_body)
    else:
        completion = json.loads(response_body)
        completion_id = completion['id']
        print(completion['choices'][0]['message'].get('content') or '')
    signature = await attestation_client.fetch_completion_signature(
        completion_id, signing_algo=SIGNING_ALGO
    )
    matching = verify_direct_model_response(
        request.content, response_body, signature, verified.attestations
    )
    print(f'Verified response against {len(matching)} model reports.')


def read_stream_id(response_body: bytes) -> str:
    for line in response_body.decode().splitlines():
        if not line.startswith('data:'):
            continue
        data = line[5:].strip()
        if not data or data == '[DONE]':
            continue
        chunk = json.loads(data)
        if 'id' in chunk:
            return chunk['id']
    raise RuntimeError('Stream returned no completion ID')


async def run_non_streaming_example(client, attestation_client, verified) -> None:
    await send_and_verify(client, attestation_client, verified, stream=False)


async def run_streaming_example(client, attestation_client, verified) -> None:
    await send_and_verify(client, attestation_client, verified, stream=True)


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
    # Direct fetch currently requests no SPKI fingerprint, matching the JS client.
    # Normal HTTPS certificate validation still applies.
    async with httpx.AsyncClient(headers=headers, timeout=None) as client:
        await run_non_streaming_example(client, attestation_client, verified)
        await run_streaming_example(client, attestation_client, verified)


if __name__ == '__main__':
    asyncio.run(main())
