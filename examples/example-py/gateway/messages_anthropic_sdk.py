import asyncio
import os

from anthropic import AsyncAnthropic

from nearai_inference_sdk import InferenceClient

BASE_URL = os.environ.get('NEARAI_BASE_URL', 'https://cloud-api.near.ai/v1/')
MODEL = os.environ.get('NEARAI_MODEL', 'anthropic/claude-haiku-4-5')


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    async with (
        InferenceClient(
            api_key,
            base_url=BASE_URL,
            ohttp=os.environ.get('NEARAI_OHTTP') == 'true',
        ) as inference,
        AsyncAnthropic(
            api_key=api_key,
            # The official SDK appends /v1/messages to this API root.
            base_url=inference.base_url.removesuffix('v1/'),
            http_client=inference.http_client,
            max_retries=0,
        ) as anthropic,
    ):
        request = {
            'model': MODEL,
            'max_tokens': 128,
            'messages': [{'role': 'user', 'content': 'Reply with the word ok.'}],
        }
        message = await anthropic.messages.create(**request)
        receipt = await inference.verify_response(message.id)
        print(
            {
                'stream': False,
                'content': message.content,
                'signature_kind': receipt.signature_kind,
            }
        )

        stream = await anthropic.messages.create(**request, stream=True)
        response_id = None
        text = ''
        # Retain streamed text until the complete response has been verified.
        async with stream:
            async for event in stream:
                if event.type == 'message_start':
                    response_id = event.message.id
                if (
                    event.type == 'content_block_delta'
                    and event.delta.type == 'text_delta'
                ):
                    text += event.delta.text
        if response_id is None:
            raise RuntimeError('Stream returned no message ID')
        receipt = await inference.verify_response(response_id)
        print({'stream': True, 'text': text, 'signature_kind': receipt.signature_kind})


if __name__ == '__main__':
    asyncio.run(main())
