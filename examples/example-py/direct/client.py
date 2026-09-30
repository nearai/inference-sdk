"""Experimental direct endpoint: verifies every supplied report before Chat."""

import asyncio
import os

from nearai_inference_sdk import DirectInferenceClient


BASE_URL = 'https://glm-5-3-flash.completions.near.ai/v1/'
MODEL = 'z-ai/glm-5.3-flash'
SIGNING_ALGO = 'ed25519'


async def run_non_streaming_example(client: DirectInferenceClient) -> None:
    completion = await client.chat.completions.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_completion_tokens=8,
    )
    print(completion.choices[0].message.content or '')
    verified = await client.verify_response(completion.id)
    print(f'Verified response against {len(verified.attestations)} model reports.')


async def run_streaming_example(client: DirectInferenceClient) -> None:
    stream = await client.chat.completions.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_completion_tokens=8,
        stream=True,
    )
    completion_id = None
    async for chunk in stream:
        completion_id = chunk.id
        if chunk.choices:
            print(chunk.choices[0].delta.content or '', end='', flush=True)
    print()
    if completion_id is None:
        raise RuntimeError('Stream returned no completion ID')
    verified = await client.verify_response(completion_id)
    print(f'Verified stream against {len(verified.attestations)} model reports.')


async def main() -> None:
    # E2EE defaults to True for direct clients. A credential must be accepted by
    # this endpoint; a Gateway API key is not necessarily valid here.
    async with DirectInferenceClient(
        BASE_URL,
        api_key=os.environ.get('NEARAI_API_KEY'),
        signing_algo=SIGNING_ALGO,
    ) as direct_client:
        await run_non_streaming_example(direct_client)
        await run_streaming_example(direct_client)


if __name__ == '__main__':
    asyncio.run(main())
