import asyncio
import os

from nearai_inference_sdk import InferenceClient

BASE_URL = os.environ.get('NEARAI_BASE_URL', 'https://cloud-api.near.ai/v1/')
MODEL = os.environ.get('NEARAI_MODEL', 'z-ai/glm-5.3-flash')
# One algorithm selects attestation, E2EE, model routing, and response signatures.
SIGNING_ALGO = os.environ.get('NEARAI_SIGNING_ALGO', 'ed25519')
OHTTP = os.environ.get('NEARAI_OHTTP') == 'true'


async def run_non_streaming_example(client: InferenceClient) -> None:
    completion = await client.chat.completions.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_completion_tokens=1024,
    )
    verified = await client.verify_response(completion.id)
    print(f'Verified {verified.signature_kind} response.')
    print(completion.choices[0].message.content or '')


async def run_streaming_example(client: InferenceClient) -> None:
    stream = await client.chat.completions.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_completion_tokens=1024,
        stream=True,
    )
    completion_id = None
    # Stream text as it arrives; verify the receipt after full consumption.
    async for chunk in stream:
        completion_id = chunk.id
        if chunk.choices:
            print(chunk.choices[0].delta.content or '', end='', flush=True)

    # Receipt verification needs the complete encrypted response, including DONE.
    print()
    if completion_id is None:
        raise RuntimeError('Stream returned no completion ID')
    verified = await client.verify_response(completion_id)
    print(f'Verified {verified.signature_kind} streaming response.')


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    # E2EE and Gateway TLS pinning are enabled. Attestations and response records
    # each have a 60-minute TTL; the response TTL starts when its body finishes.
    # Add ohttp=True to encapsulate Chat HTTP traffic; keep Ed25519 selected.
    async with InferenceClient(
        api_key,
        base_url=BASE_URL,
        signing_algo=SIGNING_ALGO,
        e2ee=True,
        ohttp=OHTTP,
    ) as inference_client:
        # Optional: verify before Chat. Both calls reuse the successful preflight.
        await inference_client.verify(MODEL)
        await run_non_streaming_example(inference_client)
        await run_streaming_example(inference_client)


if __name__ == '__main__':
    asyncio.run(main())
