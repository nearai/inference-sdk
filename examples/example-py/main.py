import asyncio
import json
import os

import aiohttp
from verifiable_ai_sdk import (
    AttestationClient,
    VerifiedGatewayAttestation,
    VerifiedModelAttestation,
    find_model_attestation_for_signature,
    verify_gateway_attestation,
    verify_gateway_response,
    verify_model_attestation,
    verify_model_response,
)


API_URL = 'https://cloud-api.near.ai/v1/chat/completions'
MODEL = 'z-ai/glm-5.2'
SIGNING_ALGO = 'ecdsa'


async def verify_gateway_deployment(
    client: AttestationClient,
) -> VerifiedGatewayAttestation:
    fetched = await client.fetch_gateway_attestation(signing_algo=SIGNING_ALGO)
    verified = await verify_gateway_attestation(
        fetched.attestation,
        fetched.client_binding,
    )
    print('Gateway deployment: verified.')
    return verified


async def verify_model_deployments(
    client: AttestationClient,
) -> tuple[VerifiedModelAttestation, ...]:
    fetched = await client.fetch_model_attestations(
        MODEL,
        signing_algo=SIGNING_ALGO,
    )
    if not fetched.attestations:
        raise RuntimeError('Cloud API returned no model attestations')

    verified_attestations = []
    for attestation in fetched.attestations:
        verified_attestations.append(
            await verify_model_attestation(
                attestation,
                fetched.client_binding,
            )
        )
    print(f'Model deployments: verified {len(verified_attestations)}.')
    return tuple(verified_attestations)


async def send_completion(
    session: aiohttp.ClientSession, api_key: str, stream: bool
) -> tuple[bytes, bytes, str]:
    request_body = json.dumps(
        {
            'model': MODEL,
            'messages': [{'role': 'user', 'content': 'Reply with the word ok.'}],
            'stream': stream,
            'max_completion_tokens': 8,
        },
        separators=(',', ':'),
    ).encode()
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
        'Accept-Encoding': 'identity',
        'x-no-aliasing': 'true',
    }
    async with session.post(API_URL, data=request_body, headers=headers) as response:
        response_body = await response.read()
        if not response.ok:
            raise RuntimeError(
                f'Completion request failed ({response.status}): '
                f'{response_body.decode(errors="replace")}'
            )

    # Keep these original bytes unchanged for response-signature verification.
    return request_body, response_body, read_completion_id(response_body, stream)


def read_completion_id(response_body: bytes, stream: bool) -> str:
    if not stream:
        completion = json.loads(response_body)
        completion_id = completion.get('id') if isinstance(completion, dict) else None
        if isinstance(completion_id, str):
            return completion_id
        raise RuntimeError('Completion response did not contain an id')

    for line in response_body.decode().splitlines():
        if not line.startswith('data: ') or line == 'data: [DONE]':
            continue
        try:
            event = json.loads(line.removeprefix('data: '))
        except json.JSONDecodeError:
            continue
        completion_id = event.get('id') if isinstance(event, dict) else None
        if isinstance(completion_id, str):
            return completion_id
    raise RuntimeError('Streaming completion response did not contain an id')


async def verify_completion_receipt(
    client: AttestationClient,
    request_body: bytes,
    response_body: bytes,
    completion_id: str,
    verified_gateway_attestation: VerifiedGatewayAttestation,
    verified_model_attestations: tuple[VerifiedModelAttestation, ...],
    *,
    stream: bool,
) -> None:
    signature = await client.fetch_completion_signature(
        completion_id,
        signing_algo=SIGNING_ALGO,
    )
    label = 'Streaming' if stream else 'Non-streaming'

    if signature.kind == 'provider_tee':
        verified_model_attestation = find_model_attestation_for_signature(
            verified_model_attestations,
            signature,
        )
        verify_model_response(
            request_body,
            response_body,
            signature,
            verified_model_attestation,
        )
        print(f'{label}: verified a model-serving TEE signature.')
        return

    verify_gateway_response(
        request_body,
        response_body,
        signature,
        verified_gateway_attestation,
    )
    print(f'{label}: verified a Gateway signature.')


async def main() -> None:
    api_key = os.environ.get('NEARAI_API_KEY')
    if not api_key:
        raise RuntimeError('NEARAI_API_KEY is required')

    client = AttestationClient(api_key)
    async with aiohttp.ClientSession(auto_decompress=False) as session:
        verified_gateway_attestation = await verify_gateway_deployment(client)
        verified_model_attestations = await verify_model_deployments(client)

        request_body, response_body, completion_id = await send_completion(
            session,
            api_key,
            stream=False,
        )
        await verify_completion_receipt(
            client,
            request_body,
            response_body,
            completion_id,
            verified_gateway_attestation=verified_gateway_attestation,
            verified_model_attestations=verified_model_attestations,
            stream=False,
        )

        request_body, response_body, completion_id = await send_completion(
            session,
            api_key,
            stream=True,
        )
        await verify_completion_receipt(
            client,
            request_body,
            response_body,
            completion_id,
            verified_gateway_attestation=verified_gateway_attestation,
            verified_model_attestations=verified_model_attestations,
            stream=True,
        )


if __name__ == '__main__':
    asyncio.run(main())
