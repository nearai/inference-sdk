"""Exercise OHTTP through the public Chat client and real receipt signatures."""

from __future__ import annotations

import asyncio
import hashlib

import httpx
import pytest

from nearai_inference_sdk import ApiError, InferenceClient, VerificationError

from .support.gateway import BASE_URL, MESSAGES, MODEL
from .support.gateway_ohttp import ObliviousGateway


@pytest.mark.parametrize('e2ee', [False, True])
@pytest.mark.parametrize('kind', ['provider_tee', 'gateway'])
async def test_ohttp_json_and_sse_verify_the_exact_inner_bytes(monkeypatch, e2ee, kind):
    gateway = ObliviousGateway(kind)
    gateway.model_report_count = 2
    gateway.install(monkeypatch)

    async with gateway.client(e2ee=e2ee) as client:
        preflight = await client.verify(MODEL)
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        assert completion.choices[0].message.content == 'Hello back'
        first, concurrent = await asyncio.gather(
            client.verify_response(completion.id), client.verify_response(completion.id)
        )
        assert concurrent is first
        assert await client.verify_response(completion.id) is first

        stream = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        chunks = [chunk async for chunk in stream]
        assert (
            ''.join(chunk.choices[0].delta.content or '' for chunk in chunks)
            == 'Hello back'
        )
        second = await client.verify_response(chunks[0].id)

        for receipt, request, response_chunks in zip(
            (first, second),
            gateway.completion_requests,
            gateway.response_chunks,
            strict=True,
        ):
            signed_text = ':'.join(
                (
                    hashlib.sha256(request.content).hexdigest(),
                    hashlib.sha256(b''.join(response_chunks)).hexdigest(),
                )
            )
            if kind == 'provider_tee':
                signed_text = f'{MODEL}:{signed_text}'
                assert receipt.attestations == preflight.models
                assert len(receipt.attestations) == 2
                assert receipt.attestation is preflight.models[0]
            else:
                assert receipt.attestation is preflight.gateway
                assert not hasattr(receipt, 'attestations')
            assert receipt.signature_kind == kind
            assert receipt.signature.signed_text == signed_text

    assert gateway.plaintexts == ['Hello', 'Hello']
    assert gateway.gateway_requests == 1
    assert gateway.model_requests == [MODEL]
    assert gateway.signature_requests == 2
    assert gateway.transport_paths == [
        '/v1/attestation/report',
        f'/v1/model/{MODEL}',
        '/v1/attestation/report',
        '/ohttp',
        '/v1/signature/chatcmpl-1',
        '/ohttp',
        '/v1/signature/chatcmpl-2',
    ]
    assert all(b'Hello' not in request.content for request in gateway.outer_requests)
    assert all(
        ('x-client-pub-key' in request.headers) == e2ee
        for request in gateway.completion_requests
    )
    assert all(
        (b'Hello' not in request.content) == e2ee
        for request in gateway.completion_requests
    )


@pytest.mark.parametrize(
    ('failure', 'code'),
    [
        ('missing', 'ohttp.attestation_required'),
        ('signer', 'ohttp.signer_mismatch'),
        ('signature', 'ohttp.signature_invalid'),
        ('malformed_config', 'ohttp.key_config_invalid'),
    ],
)
async def test_invalid_ohttp_evidence_blocks_authenticated_preflight(
    monkeypatch, failure, code
):
    gateway = ObliviousGateway()
    gateway.proof_failure = failure
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        request = httpx.Request(
            'POST',
            BASE_URL + 'chat/completions',
            json={'model': MODEL, 'messages': MESSAGES},
        )
        async with asyncio.timeout(1):
            with pytest.raises(VerificationError) as raised:
                await client.send(request)

    assert raised.value.failure.code == code
    assert gateway.transport_paths == ['/v1/attestation/report']
    assert gateway.headers == []
    assert gateway.outer_requests == []
    assert gateway.completion_requests == []
    assert gateway.signature_requests == 0


@pytest.mark.parametrize('e2ee', [False, True])
async def test_missing_ohttp_final_tag_after_done_prevents_receipt_verification(
    monkeypatch, e2ee
):
    gateway = ObliviousGateway()
    gateway.ohttp_gateway.truncate_final_response = True
    gateway.install(monkeypatch)

    async with gateway.client(e2ee=e2ee) as client:
        stream = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        chunks = [chunk async for chunk in stream]
        assert chunks[0].choices[0].delta.content == 'Hello back'
        with pytest.raises(VerificationError) as raised:
            await client.verify_response(chunks[0].id)

    assert raised.value.failure.code == 'ohttp.decryption_failed'
    assert gateway.signature_requests == 0


def test_ohttp_rejects_ecdsa_signing_before_creating_clients():
    with pytest.raises(ApiError) as raised:
        InferenceClient('test-key', ohttp=True, signing_algo='ecdsa')

    assert raised.value.failure.code == 'api.invalid_input'
    assert raised.value.failure.details['field'] == 'signing_algo'
