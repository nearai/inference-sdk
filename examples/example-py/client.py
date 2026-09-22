import asyncio
import os

from nearai_inference_sdk import (
    AttestationVerifiers,
    GatewayVerificationOptions,
    ImageProvenancePolicy,
    InferenceClient,
    MeasuredDeployment,
    verify_deployment_image_provenance,
)


BASE_URL = 'https://cloud-api.near.ai/v1/'
MODEL = 'z-ai/glm-5.3-flash'
# One algorithm selects attestation, E2EE, model routing, and response signatures.
SIGNING_ALGO = 'ed25519'
GATEWAY_IMAGE_POLICIES = {
    'nearaidev/cloud-api': ImageProvenancePolicy(
        repository='nearai/cloud-api', workflow='.github/workflows/build.yml'
    ),
    'nearaidev/cvm-ingress': ImageProvenancePolicy(
        repository='nearai/cvm-ingress', workflow='.github/workflows/build-push.yml'
    ),
    'nearaidev/dstack-vpc': ImageProvenancePolicy(
        repository='nearai/dstack-vpc', workflow='.github/workflows/build.yml'
    ),
    'nearaidev/dstack-vpc-client': ImageProvenancePolicy(
        repository='nearai/dstack-vpc-client', workflow='.github/workflows/build.yml'
    ),
}


async def verify_gateway_images(deployment: MeasuredDeployment) -> None:
    # These caller-owned policies check Gateway images, not model runtime images.
    await verify_deployment_image_provenance(
        deployment.app_compose, GATEWAY_IMAGE_POLICIES
    )


async def run_non_streaming_example(client: InferenceClient) -> None:
    completion = await client.chat.completions.create(
        model=MODEL,
        messages=[{'role': 'user', 'content': 'Reply with the word ok.'}],
        max_completion_tokens=8,
    )
    print(completion.choices[0].message.content or '')
    verified = await client.verify_response(completion.id)
    print(f'Verified {verified.signature_kind} response.')


async def run_streaming_example(client: InferenceClient) -> None:
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

    # Receipt verification needs the complete encrypted response, including DONE.
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
        gateway_verification=GatewayVerificationOptions(
            verifiers=AttestationVerifiers(deployment=verify_gateway_images)
        ),
    ) as inference_client:
        await run_non_streaming_example(inference_client)
        await run_streaming_example(inference_client)


if __name__ == '__main__':
    asyncio.run(main())
