import asyncio
import json
import os
from dataclasses import dataclass

import httpx
from nearai_inference_sdk import (
    AttestationClient,
    AttestationVerifiers,
    E2eeModelKey,
    ImageProvenancePolicy,
    MeasuredDeployment,
    VerifiedGatewayAttestation,
    VerifiedModelAttestation,
    create_pinned_tls_client,
    prepare_e2ee_chat_request,
    verify_deployment_image_provenance,
    verify_gateway_attestation,
    verify_gateway_response,
    verify_model_attestation,
    verify_model_response,
)


BASE_URL = 'https://cloud-api.near.ai/v1/'
MODEL = 'z-ai/glm-5.3-flash'
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


@dataclass
class Completion:
    id: str
    request_body: bytes
    response_body: bytes


@dataclass(frozen=True)
class E2eeRecipient:
    attestation: VerifiedModelAttestation
    key: E2eeModelKey


class RecordingStream(httpx.AsyncByteStream):
    """Keep ciphertext while the E2EE decryptor consumes the response stream."""

    def __init__(self, source: httpx.AsyncByteStream) -> None:
        self.source = source
        self.chunks: list[bytes] = []

    async def __aiter__(self):
        async for chunk in self.source:
            self.chunks.append(chunk)
            yield chunk

    async def aclose(self) -> None:
        await self.source.aclose()


async def verify_gateway_images(deployment: MeasuredDeployment) -> None:
    await verify_deployment_image_provenance(
        deployment.app_compose, GATEWAY_IMAGE_POLICIES
    )


async def fetch_and_verify_gateway(
    client: AttestationClient,
) -> VerifiedGatewayAttestation:
    # Fetching checks the API response and records the client nonce/TLS peer;
    # verification authenticates the quote, binding, and measured configuration.
    fetched = await client.fetch_gateway_attestation(signing_algo=SIGNING_ALGO)
    verified = await verify_gateway_attestation(
        fetched.attestation,
        fetched.client_binding,
        verifiers=AttestationVerifiers(deployment=verify_gateway_images),
    )
    print('Gateway deployment and image provenance: verified.')
    return verified


async def fetch_and_verify_models(
    client: AttestationClient,
) -> list[VerifiedModelAttestation]:
    fetched = await client.fetch_model_attestations(MODEL, signing_algo=SIGNING_ALGO)
    if not fetched.attestations:
        raise RuntimeError('Gateway returned no model attestations')

    # These are model reports fetched through the Gateway, not direct model TLS
    # connections. Verify every report before choosing an encryption recipient.
    models = []
    for attestation in fetched.attestations:
        verified = await verify_model_attestation(attestation, fetched.client_binding)
        models.append(verified)
    print(f'Model deployments: verified {len(models)}.')
    return models


def find_e2ee_recipient(
    models: list[VerifiedModelAttestation],
) -> E2eeRecipient:
    # No response signature exists yet; choose a verified key for the request.
    for model in models:
        if (
            model.signer.signing_algo == SIGNING_ALGO
            and model.signing_public_key is not None
        ):
            return E2eeRecipient(
                attestation=model,
                key=E2eeModelKey(
                    signing_algo=SIGNING_ALGO, public_key=model.signing_public_key
                ),
            )
    raise RuntimeError('No verified model public key is available for E2EE')


async def send_completion(
    client: httpx.AsyncClient, api_key: str, recipient: E2eeRecipient, *, stream: bool
) -> Completion:
    request = httpx.Request(
        'POST',
        BASE_URL + 'chat/completions',
        headers={'Authorization': f'Bearer {api_key}', 'Accept-Encoding': 'identity'},
        json={
            'model': MODEL,
            'messages': [{'role': 'user', 'content': 'Reply with the word ok.'}],
            'max_completion_tokens': 8,
            'stream': stream,
        },
    )
    # The helper encrypts supported fields and creates a fresh response key. It
    # does not send the request or repeat attestation verification.
    prepared = await prepare_e2ee_chat_request(request, recipient.key)
    request_body = prepared.request.content
    response = await client.send(prepared.request, stream=True)
    response.raise_for_status()
    recording = RecordingStream(response.stream)
    response.stream = recording
    decrypted = await prepared.decrypt_response(response)
    completion_id = None
    stream_complete = False
    try:
        if stream:
            async for line in decrypted.aiter_lines():
                if not line.startswith('data:'):
                    continue
                data = line.removeprefix('data:').strip()
                if data == '[DONE]':
                    stream_complete = True
                    continue
                chunk = json.loads(data)
                completion_id = chunk.get('id', completion_id)
                for choice in chunk.get('choices', []):
                    print(
                        choice.get('delta', {}).get('content') or '', end='', flush=True
                    )
            print()
        else:
            await decrypted.aread()
            body = decrypted.json()
            completion_id = body['id']
            print(body['choices'][0]['message'].get('content') or '')
    finally:
        await decrypted.aclose()
        await response.aclose()

    if completion_id is None:
        raise RuntimeError('Completion response did not contain an ID')
    if stream and not stream_complete:
        raise RuntimeError('Streaming completion ended before [DONE]')
    # Signatures cover the encrypted HTTP bytes, not the displayed plaintext.
    return Completion(completion_id, request_body, b''.join(recording.chunks))


async def run_non_streaming_example(client, api_key, recipient) -> Completion:
    return await send_completion(client, api_key, recipient, stream=False)


async def run_streaming_example(client, api_key, recipient) -> Completion:
    return await send_completion(client, api_key, recipient, stream=True)


async def verify_completion_receipt(
    client: AttestationClient,
    completion: Completion,
    gateway: VerifiedGatewayAttestation,
    recipient: E2eeRecipient,
) -> None:
    signature = await client.fetch_completion_signature(
        completion.id, signing_algo=SIGNING_ALGO
    )
    if signature.kind == 'provider_tee':
        verify_model_response(
            completion.request_body,
            completion.response_body,
            signature,
            recipient.attestation,
        )
    else:
        # A Gateway signature proves these bytes were signed by its verified key;
        # it does not prove which model deployment generated the content.
        verify_gateway_response(
            completion.request_body, completion.response_body, signature, gateway
        )
    print(f'Verified {signature.kind} response.')


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    attestation_client = AttestationClient(api_key, base_url=BASE_URL)
    gateway = await fetch_and_verify_gateway(attestation_client)
    models = await fetch_and_verify_models(attestation_client)
    recipient = find_e2ee_recipient(models)

    # Native clients should pin Chat TLS to the authenticated Gateway SPKI.
    # Browser clients cannot inspect the peer certificate and skip this step.
    async with create_pinned_tls_client(
        gateway.tls_binding.spki_fingerprint
    ) as pinned_tls_client:
        completion = await run_non_streaming_example(
            pinned_tls_client, api_key, recipient
        )
        await verify_completion_receipt(
            attestation_client, completion, gateway, recipient
        )

        completion = await run_streaming_example(
            pinned_tls_client, api_key, recipient
        )
        await verify_completion_receipt(
            attestation_client, completion, gateway, recipient
        )


if __name__ == '__main__':
    asyncio.run(main())
