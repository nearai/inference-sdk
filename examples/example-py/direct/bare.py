"""Experimental manual direct verification. This example sends plaintext over HTTPS."""

import asyncio
import json
import os

import httpx
from nearai_inference_sdk import (
    DirectAttestationClient,
    VerifiedDirectModelAttestations,
    verify_direct_model_attestations,
    verify_direct_model_response,
)

BASE_URL = os.environ.get(
    'NEARAI_BASE_URL', 'https://glm-5-3-flash.completions.near.ai/v1/'
)
MODEL = os.environ.get('NEARAI_MODEL', 'z-ai/glm-5.3-flash')
SIGNING_ALGO = os.environ.get('NEARAI_SIGNING_ALGO', 'ed25519')


class RecordingStream(httpx.AsyncByteStream):
    def __init__(self, source: httpx.AsyncByteStream) -> None:
        self.source = source
        self.chunks: list[bytes] = []

    async def __aiter__(self):
        async for chunk in self.source:
            self.chunks.append(chunk)
            yield chunk

    async def aclose(self) -> None:
        await self.source.aclose()


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
    recording = RecordingStream(response.stream)
    response.stream = recording
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


async def read_stream(response: httpx.Response) -> list[dict]:
    values, data = [], []
    done = False
    first_line = True
    async for line in response.aiter_lines():
        if first_line:
            line = line.removeprefix('\ufeff')
            first_line = False
        if line == 'data':
            data.append('')
        elif line.startswith('data:'):
            data.append(line[5:].removeprefix(' '))
        elif not line:
            payload = '\n'.join(data)
            data = []
            if payload == '[DONE]':
                done = True
            elif payload:
                value = json.loads(payload)
                if value.get('error'):
                    raise RuntimeError('Stream returned an error')
                values.append(value)
                for choice in value.get('choices', [])[:1]:
                    print(
                        choice.get('delta', {}).get('content') or '', end='', flush=True
                    )
    print()
    if not done:
        raise RuntimeError('Stream ended without [DONE]')
    return values


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
