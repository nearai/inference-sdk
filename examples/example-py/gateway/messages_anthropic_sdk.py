import asyncio
import os

from anthropic import AsyncAnthropic
from nearai_inference_sdk import InferenceClient

BASE_URL = os.environ.get('NEARAI_BASE_URL', 'https://cloud-api.near.ai/v1/')
MODEL = os.environ.get('NEARAI_MODEL', 'anthropic/claude-haiku-4-5')
SIGNING_ALGO = 'ed25519'


async def run_non_streaming_example(
    anthropic_client: AsyncAnthropic, inference_client: InferenceClient
) -> None:
    message = await anthropic_client.messages.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_tokens=128,
    )
    verified = await inference_client.verify_response(message.id)
    print(f'Verified {verified.signature_kind} response.')
    for block in message.content:
        if block.type == 'text':
            print(block.text)


async def run_streaming_example(
    anthropic_client: AsyncAnthropic, inference_client: InferenceClient
) -> None:
    stream = await anthropic_client.messages.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_tokens=128,
        stream=True,
    )
    message_id = None
    text = ''
    # Retain streamed text until the complete response has been verified.
    async with stream:
        async for event in stream:
            if event.type == 'message_start':
                message_id = event.message.id
            if event.type == 'content_block_delta' and event.delta.type == 'text_delta':
                text += event.delta.text

    if message_id is None:
        raise RuntimeError('Stream returned no message ID')
    verified = await inference_client.verify_response(message_id)
    print(f'Verified {verified.signature_kind} streaming response.')
    print(text)


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    async with (
        InferenceClient(
            api_key,
            base_url=BASE_URL,
            signing_algo=SIGNING_ALGO,
            ohttp=os.environ.get('NEARAI_OHTTP') == 'true',
        ) as inference_client,
        AsyncAnthropic(
            api_key=api_key,
            # The official SDK appends /v1/messages to this API root.
            base_url=inference_client.base_url.removesuffix('v1/'),
            http_client=inference_client.http_client,
            max_retries=0,
        ) as anthropic_client,
    ):
        await run_non_streaming_example(anthropic_client, inference_client)
        await run_streaming_example(anthropic_client, inference_client)


if __name__ == '__main__':
    asyncio.run(main())
