import asyncio
import os

from nearai_inference_sdk import InferenceClient


async def main() -> None:
    async with InferenceClient(os.environ['NEARAI_API_KEY']) as client:
        request = dict(
            model='z-ai/glm-5.3-flash', input='Reply with the word ok.', store=False
        )
        response = await client.responses.create(**request)
        await client.verify_response(response.id)
        print(response.output_text)

        stream = await client.responses.create(**request, stream=True)
        response_id = None
        async for event in stream:
            if event.type == 'response.created':
                response_id = event.response.id
            if event.type == 'response.output_text.delta':
                print(event.delta, end='', flush=True)
        if response_id is None:
            raise RuntimeError('Stream returned no response ID')
        # Streamed text is provisional until the complete response is verified.
        await client.verify_response(response_id)
        print('\nVerified Gateway Responses receipt.')


if __name__ == '__main__':
    asyncio.run(main())
