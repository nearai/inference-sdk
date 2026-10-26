import asyncio
import os

from nearai_inference_sdk import ApiError, InferenceClient


async def verify_receipt(client: InferenceClient, response_id: str) -> bool:
    """Retry receipt lookup for up to ten seconds, keeping the original inference."""
    backoff = 0.5
    try:
        async with asyncio.timeout(10):
            while True:
                try:
                    await client.verify_response(response_id)
                    return True
                except ApiError as error:
                    if (
                        not error.retryable
                        and error.failure.code != 'api.completion_signature_unavailable'
                    ):
                        raise
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 2)
    except TimeoutError:
        return False


async def main() -> None:
    async with InferenceClient(os.environ['NEARAI_API_KEY']) as client:
        request = {
            'model': 'anthropic/claude-haiku-4-5',
            'messages': [{'role': 'user', 'content': 'Reply with the word ok.'}],
            'max_tokens': 128,
        }
        response = await client.messages.create(**request)
        verified = await verify_receipt(client, response.id)
        print({'id': response.id, 'verified': verified, 'output': response.content})

        stream = await client.messages.create(**request, stream=True)
        response_id = None
        async for event in stream:
            if event.type == 'message_start':
                response_id = event.message.id
            if event.type == 'content_block_delta' and event.delta.type == 'text_delta':
                print(event.delta.text, end='', flush=True)
        if response_id is None:
            raise RuntimeError('Stream returned no response ID')
        # Streamed text is provisional until the complete response is verified.
        verified = await verify_receipt(client, response_id)
        print('\nReceipt status:', {'id': response_id, 'verified': verified})


if __name__ == '__main__':
    asyncio.run(main())
