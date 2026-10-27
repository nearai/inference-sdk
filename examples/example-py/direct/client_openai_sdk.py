"""Experimental direct client used as the official OpenAI SDK's HTTP transport."""

import asyncio
import os

from nearai_inference_sdk import DirectInferenceClient
from openai import AsyncOpenAI

BASE_URL = os.environ.get(
    'NEARAI_BASE_URL', 'https://glm-5-3-flash.completions.near.ai/v1/'
)
MODEL = os.environ.get('NEARAI_MODEL', 'z-ai/glm-5.3-flash')
SIGNING_ALGO = os.environ.get('NEARAI_SIGNING_ALGO', 'ed25519')


async def run_non_streaming_example(
    openai_client: AsyncOpenAI, direct_client: DirectInferenceClient
) -> None:
    completion = await openai_client.chat.completions.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_completion_tokens=1024,
    )
    verified = await direct_client.verify_response(completion.id)
    print(f'Verified {verified.signature_kind} response.')
    print(completion.choices[0].message.content or '')


async def run_streaming_example(
    openai_client: AsyncOpenAI, direct_client: DirectInferenceClient
) -> None:
    stream = await openai_client.chat.completions.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_completion_tokens=1024,
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
    verified = await direct_client.verify_response(completion_id)
    print(f'Verified {verified.signature_kind} streaming response.')


async def main() -> None:
    api_key = os.environ.get('NEARAI_API_KEY')
    # Configure authentication here; the external OpenAI key is ignored.
    # Enable E2EE explicitly. The client retains bytes for verify_response.
    async with DirectInferenceClient(
        BASE_URL,
        api_key=api_key,
        signing_algo=SIGNING_ALGO,
        e2ee=True,
        ohttp=os.environ.get('NEARAI_OHTTP') == 'true',
    ) as direct_client:
        openai_client = AsyncOpenAI(
            max_retries=0,
            api_key=api_key or 'unused',
            base_url=BASE_URL,
            http_client=direct_client.http_client,
        )
        await run_non_streaming_example(openai_client, direct_client)
        await run_streaming_example(openai_client, direct_client)


if __name__ == '__main__':
    asyncio.run(main())
