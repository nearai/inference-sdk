"""Incognito verifies the Gateway, without claiming model execution in a TEE."""

import httpx
import pytest

from nearai_inference_sdk import (
    ApiError,
    ModelAttestationPolicy,
    ModelVerificationOptions,
    VerificationError,
)

from .test_inference_client import BASE_URL, MESSAGES, MODEL, Gateway
from .test_inference_ohttp import ObliviousGateway


@pytest.mark.parametrize('ohttp', [False, True])
async def test_incognito_verifies_gateway_receipts_for_json_and_streams(
    monkeypatch, ohttp
):
    gateway = ObliviousGateway('gateway') if ohttp else Gateway(kind='gateway')
    gateway.metadata = {'providerType': 'openai', 'attestationSupported': False}
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        verified = await client.verify_response(completion.id)
        assert verified.signature_kind == 'gateway'
        stream = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        chunks = [chunk async for chunk in stream]
        verified = await client.verify_response(chunks[0].id)
        assert verified.signature_kind == 'gateway'
    assert gateway.model_requests == []
    assert gateway.gateway_requests == 1
    assert all(
        'x-model-pub-key' not in request.headers
        for request in gateway.completion_requests
    )


@pytest.mark.parametrize(
    'options',
    [
        {'e2ee': True},
        {
            'e2ee': False,
            'model_verification': ModelVerificationOptions(
                policy=ModelAttestationPolicy()
            ),
        },
        {'e2ee': False, 'deployment_policy': lambda _model, _deployment: None},
    ],
)
async def test_model_requirements_stop_incognito_before_chat(monkeypatch, options):
    gateway = Gateway(kind='gateway')
    gateway.metadata = {'providerType': 'chutes', 'attestationSupported': True}
    gateway.install(monkeypatch)
    async with gateway.client(**options) as client:
        with pytest.raises(VerificationError) as raised:
            await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
        assert raised.value.failure.code == 'policy.model_attestation_required'
    assert gateway.completion_requests == []


async def test_invalid_metadata_does_not_fall_back_to_incognito(monkeypatch):
    gateway = Gateway()
    gateway.metadata = {'providerType': 'vllm', 'attestationSupported': 'true'}
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(ApiError) as raised:
            await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
        assert raised.value.failure.code == 'api.invalid_response'
    assert gateway.completion_requests == []


async def test_incognito_cannot_accept_a_provider_tee_receipt(monkeypatch):
    gateway = Gateway(kind='provider_tee')
    gateway.metadata = {'providerType': 'openai', 'attestationSupported': False}
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        with pytest.raises(VerificationError) as raised:
            await client.verify_response(completion.id)
        assert raised.value.failure.code == 'signature.kind_mismatch'
