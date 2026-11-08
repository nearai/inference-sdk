import asyncio
import json
import os
from dataclasses import dataclass

import httpx
from nearai_inference_sdk import (
    AttestationClient,
    AttestationVerifiers,
    ComposeManagerImagePolicy,
    E2eeModelKey,
    ImageProvenancePolicy,
    MeasuredDeployment,
    ModelAttestationVerifiers,
    VerifiedGatewayAttestation,
    VerifiedModelAttestation,
    create_pinned_tls_client,
    find_model_attestations_for_signature,
    prepare_e2ee_chat_request,
    verify_compose_manager_deployment_image_provenance,
    verify_deployment_image_provenance,
    verify_gateway_attestation,
    verify_gateway_response,
    verify_model_attestation,
    verify_model_response,
)

from utils.chat_output import RecordingStream, read_stream

BASE_URL = (
    os.environ.get('NEARAI_BASE_URL', 'https://cloud-api.near.ai/v1/').rstrip('/') + '/'
)
MODEL = os.environ.get('NEARAI_MODEL', 'z-ai/glm-5.3-flash')
SIGNING_ALGO = os.environ.get('NEARAI_SIGNING_ALGO', 'ed25519')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN') or None

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


MODEL_IMAGE_POLICIES = {
    'nearaidev/vllm-proxy-rs': ImageProvenancePolicy(
        repository='nearai/inference-proxy', workflow='.github/workflows/build.yml'
    ),
}


async def verify_model_images(deployment: MeasuredDeployment) -> None:
    # Verify recorded deployment intent, not the currently running containers.
    await verify_compose_manager_deployment_image_provenance(
        deployment,
        MODEL_IMAGE_POLICIES,
        compose_manager_image_policy=ComposeManagerImagePolicy(
            image_repository='nearaidev/compose-manager',
            repository='nearai/compose-manager',
            workflow='.github/workflows/build.yml',
        ),
        github_token=GITHUB_TOKEN,
    )


@dataclass
class Completion:
    id: str
    request_body: bytes
    response_body: bytes
    text: str | None


async def verify_gateway_images(deployment: MeasuredDeployment) -> None:
    await verify_deployment_image_provenance(
        deployment.app_compose,
        GATEWAY_IMAGE_POLICIES,
        github_token=GITHUB_TOKEN,
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


async def fetch_and_verify_model_attestations(
    client: AttestationClient,
) -> list[VerifiedModelAttestation]:
    fetched = await client.fetch_model_attestations(MODEL, signing_algo=SIGNING_ALGO)
    if not fetched.attestations:
        raise RuntimeError('Gateway returned no model attestations')

    # These are model reports fetched through the Gateway, not direct model TLS
    # connections. Verify every report before choosing an encryption recipient.
    model_attestations = []
    for attestation in fetched.attestations:
        verified = await verify_model_attestation(
            attestation,
            fetched.client_binding,
            verifiers=ModelAttestationVerifiers(deployment=verify_model_images),
        )
        model_attestations.append(verified)
    print(f'Model deployments: verified {len(model_attestations)}.')
    return model_attestations


def find_model_attestation_for_encryption(
    model_attestations: list[VerifiedModelAttestation],
) -> VerifiedModelAttestation:
    # No response signature exists yet; choose a verified key for the request.
    for attestation in model_attestations:
        if (
            attestation.signer.signing_algo == SIGNING_ALGO
            and attestation.signing_public_key is not None
        ):
            return attestation
    raise RuntimeError('No verified model public key is available for E2EE')


async def send_completion(
    client: httpx.AsyncClient, api_key: str, model_key: E2eeModelKey, *, stream: bool
) -> Completion:
    request = httpx.Request(
        'POST',
        BASE_URL + 'chat/completions',
        headers={'Authorization': f'Bearer {api_key}', 'Accept-Encoding': 'identity'},
        json={
            'model': MODEL,
            'messages': [{'role': 'user', 'content': 'Reply with the word ok.'}],
            'max_completion_tokens': 1024,
            'stream': stream,
        },
    )
    # The helper encrypts supported fields and creates a fresh response key. It
    # does not send the request or repeat attestation verification.
    prepared = await prepare_e2ee_chat_request(request, model_key)
    request_body = prepared.request.content
    response = await client.send(prepared.request, stream=True)
    recording = RecordingStream(response)
    response = httpx.Response(
        response.status_code,
        headers={'Content-Type': response.headers.get('content-type', '')},
        stream=recording,
        request=prepared.request,
    )
    try:
        response.raise_for_status()
        decrypted = await prepared.decrypt_response(response)
        try:
            values = (
                await read_stream(decrypted)
                if stream
                else [json.loads(await decrypted.aread())]
            )
        finally:
            await decrypted.aclose()
        completion_id = next((value['id'] for value in values if value.get('id')), None)
        text = ''.join(
            choice.get('delta' if stream else 'message', {}).get('content') or ''
            for value in values
            for choice in value.get('choices', [])[:1]
        )
    finally:
        await response.aclose()
    if completion_id is None:
        raise RuntimeError('Completion response did not contain an ID')
    return Completion(
        completion_id,
        request_body,
        b''.join(recording.chunks),
        None if stream else text,
    )


async def verify_completion_response(
    client: AttestationClient,
    completion: Completion,
    gateway: VerifiedGatewayAttestation,
    model_attestations: list[VerifiedModelAttestation],
    selected_model_attestation: VerifiedModelAttestation,
) -> None:
    signature = await client.fetch_completion_signature(
        completion.id, signing_algo=SIGNING_ALGO
    )
    if signature.kind == 'provider_tee':
        verify_model_response(
            completion.request_body,
            completion.response_body,
            signature,
            selected_model_attestation,
        )
        matching_attestations = find_model_attestations_for_signature(
            model_attestations, signature
        )
        print(
            'Verified model response signature '
            f'({len(matching_attestations)} matching reports).'
        )
    else:
        # A Gateway signature proves these bytes were signed by its verified key;
        # it does not prove which model deployment generated the content.
        verify_gateway_response(
            completion.request_body, completion.response_body, signature, gateway
        )
        print('Verified Gateway response signature.')
    if completion.text is not None:
        print(completion.text)


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    attestation_client = AttestationClient(api_key, base_url=BASE_URL)
    gateway = await fetch_and_verify_gateway(attestation_client)

    # Pin model evidence, Chat, and signature requests to the verified Gateway.
    async with create_pinned_tls_client(
        gateway.tls_binding.spki_fingerprint
    ) as pinned_tls_client:
        model_attestations = await fetch_and_verify_model_attestations(
            attestation_client
        )
        selected_model_attestation = find_model_attestation_for_encryption(
            model_attestations
        )
        model_key = E2eeModelKey(
            signing_algo=SIGNING_ALGO,
            public_key=selected_model_attestation.signing_public_key,
        )
        completion = await send_completion(
            pinned_tls_client, api_key, model_key, stream=False
        )
        await verify_completion_response(
            attestation_client,
            completion,
            gateway,
            model_attestations,
            selected_model_attestation,
        )

        completion = await send_completion(
            pinned_tls_client, api_key, model_key, stream=True
        )
        await verify_completion_response(
            attestation_client,
            completion,
            gateway,
            model_attestations,
            selected_model_attestation,
        )


if __name__ == '__main__':
    asyncio.run(main())
