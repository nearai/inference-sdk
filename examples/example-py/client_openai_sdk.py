import asyncio
import os

from openai import AsyncOpenAI
from nearai_inference_sdk import InferenceClient


BASE_URL = 'https://cloud-api.near.ai/v1/'
MODEL = 'z-ai/glm-5.3-flash'
SIGNING_ALGO = 'ed25519'


async def run_non_streaming_example(
    openai_client: AsyncOpenAI, inference_client: InferenceClient
) -> None:
    completion = await openai_client.chat.completions.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_completion_tokens=8,
    )
    print(completion.choices[0].message.content or '')
    verified = await inference_client.verify_response(completion.id)
    print(f'Verified {verified.signature_kind} response.')


async def run_streaming_example(
    openai_client: AsyncOpenAI, inference_client: InferenceClient
) -> None:
    stream = await openai_client.chat.completions.create(
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
    verified = await inference_client.verify_response(completion_id)
    print(f'Verified {verified.signature_kind} streaming response.')


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    # InferenceClient owns the transport. Reuse it for one OpenAI client; it
    # verifies deployments, pins Gateway TLS, encrypts, and retains receipt bytes.
    async with InferenceClient(
        api_key, base_url=BASE_URL, signing_algo=SIGNING_ALGO
    ) as inference_client:
        openai_client = AsyncOpenAI(
            api_key=api_key,
            base_url=BASE_URL,
            http_client=inference_client.http_client,
        )
        await run_non_streaming_example(openai_client, inference_client)
        await run_streaming_example(openai_client, inference_client)


if __name__ == '__main__':
    asyncio.run(main())
