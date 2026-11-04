import asyncio
import os

from anthropic import AsyncAnthropic
from nearai_inference_sdk import InferenceClient

BASE_URL = os.environ.get('NEARAI_BASE_URL', 'https://cloud-api.near.ai/v1/')
MODEL = os.environ.get('NEARAI_MODEL', 'anthropic/claude-haiku-4-5')
SIGNING_ALGO = os.environ.get('NEARAI_SIGNING_ALGO', 'ed25519')


async def run_non_streaming_example(
    api: AsyncAnthropic, inference_client: InferenceClient
) -> None:
    response = await api.messages.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_tokens=128,
    )
    verified = await inference_client.verify_response(response.id)
    print(f'Verified {verified.signature_kind} response.')
    print(''.join(block.text for block in response.content if block.type == 'text'))


async def run_streaming_example(
    api: AsyncAnthropic, inference_client: InferenceClient
) -> None:
    stream = await api.messages.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_tokens=128,
        stream=True,
    )
    response_id = None
    # Stream text as it arrives; verify the receipt after full consumption.
    async with stream:
        async for event in stream:
            if event.type == 'message_start':
                response_id = event.message.id
            if event.type == 'content_block_delta' and event.delta.type == 'text_delta':
                print(event.delta.text, end='', flush=True)
    print()
    if response_id is None:
        raise RuntimeError('Stream returned no response ID')
    verified = await inference_client.verify_response(response_id)
    print(f'Verified {verified.signature_kind} streaming response.')


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    async with (
        asyncio.timeout(120),
        InferenceClient(
            api_key,
            base_url=BASE_URL,
            signing_algo=SIGNING_ALGO,
            ohttp=os.environ.get('NEARAI_OHTTP') == 'true',
        ) as inference_client,
        AsyncAnthropic(
            api_key=api_key,
            base_url=inference_client.base_url.removesuffix('v1/'),
            http_client=inference_client.http_client,
            max_retries=0,
        ) as api,
    ):
        await run_non_streaming_example(api, inference_client)
        await run_streaming_example(api, inference_client)


if __name__ == '__main__':
    asyncio.run(main())
