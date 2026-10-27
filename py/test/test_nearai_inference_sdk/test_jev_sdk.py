"""Exercise the published Jev SDK against the verified HTTPX2 adapter."""

import asyncio
import base64
import json
from pathlib import Path

import httpx2
import pytest
from typesafe_sdk import (
    AsyncTypeSafeClient,
    Box,
    Choice,
    Image,
    Noul,
    RetryPolicy,
    Score,
)

from nearai_inference_sdk import ApiError, VerificationError

from .test_inference_client import BASE_URL, MODEL
from .test_systemone import BOX_BOUNDS, IMAGE_PART, REQUEST, DecisionGateway


def official_client(client):
    return AsyncTypeSafeClient(
        api_key='external-key',
        base_url=BASE_URL.removesuffix('v1/'),
        http_client=client.httpx2_client,
        model=MODEL,
        compression=False,
        retry=RetryPolicy(max_retries=0),
        timeout=httpx2.Timeout(60),
    )


def decision(jev):
    return jev.system_one(
        state={'message': 'Charged twice — please help 🌎'},
        questions={
            'useful': Noul(instructions='Is this useful?'),
            'action': Choice(
                instructions='Choose an action.',
                criteria={'keep': 'Use it', 'skip': None},
            ),
            'quality': Score(instructions='Rate quality.', criteria=['low', 'high']),
        },
        extra_headers={'x-model-pub-key': 'stale', 'x-client-pub-key': 'stale'},
    )


async def test_official_box_with_openrouter_image_parts(monkeypatch):
    gateway = DecisionGateway()
    gateway.answers = {'region': {'type': 'box', 'box': BOX_BOUNDS, 'confidence': 0.82}}
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        async with official_client(client) as jev:
            result = await jev.system_one(
                state=[IMAGE_PART],
                questions={'region': Box(instructions='Locate the rectangle')},
            )
            assert result.boxes['region'].box.top == BOX_BOUNDS['top']
            receipt_id = result.raw_http_response.headers['x-generation-id']
        verified = await client.verify_response(receipt_id)
        assert verified.signature_kind == 'gateway'
    sent = json.loads(gateway.requests[0].content)
    assert sent['state'] == [IMAGE_PART]
    assert sent['questions']['region'] == {
        'type': 'box',
        'instructions': 'Locate the rectangle',
    }
    assert 'assets' not in sent
    assert len(gateway.requests) == 1


@pytest.mark.parametrize('named', [False, True])
@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
async def test_official_image_converts_multipart_and_verifies_sent_bytes(
    monkeypatch, named, signing_algo
):
    gateway = DecisionGateway(signing_algo)
    gateway.answers = {
        'region': {'type': 'box', 'box': BOX_BOUNDS, 'confidence': 0.82},
        'match': {'type': 'noul', 'noul': 0.98},
    }
    gateway.install(monkeypatch)
    path = Path(__file__).resolve().parents[3] / 'test-fixtures/systemone/rectangle.png'
    photo = Image(path)
    part = {
        'type': 'image_url',
        'image_url': {
            'url': 'data:image/png;base64,'
            + base64.b64encode(path.read_bytes()).decode()
        },
    }
    async with gateway.client(e2ee=False) as client:
        async with official_client(client) as jev:
            result = await jev.system_one(
                state={'frames': ['<photo>' if named else photo]},
                questions={
                    'region': Box(
                        instructions='Locate <photo> now'
                        if named
                        else f'Locate {photo} now'
                    ),
                    'match': Noul(
                        instructions='Does it match?',
                        criteria={
                            'true': '<photo>' if named else photo,
                            'false': 'Different',
                        },
                    ),
                },
                assets={'<photo>': photo} if named else None,
                extra_headers={'content-md5': 'old-body', 'content-digest': 'old-body'},
            )
            assert result.boxes['region'].box.top == BOX_BOUNDS['top']
            receipt_id = result.raw_http_response.headers['x-generation-id']
        assert (await client.verify_response(receipt_id)).signature_kind == 'gateway'
    sent = gateway.requests[0]
    assert sent.headers['content-type'] == 'application/json'
    assert int(sent.headers['content-length']) == len(sent.content)
    assert 'content-md5' not in sent.headers
    assert 'content-digest' not in sent.headers
    assert json.loads(sent.content) == {
        'model': MODEL,
        'state': {'frames': [part]},
        'questions': {
            'region': {'type': 'box', 'instructions': ['Locate ', part, ' now']},
            'match': {
                'type': 'noul',
                'instructions': 'Does it match?',
                'criteria': {'true': part, 'false': 'Different'},
            },
        },
    }
    assert len(gateway.requests) == 1


@pytest.mark.parametrize('kind', ['gateway', 'provider_tee'])
@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
@pytest.mark.parametrize('encoding', ['gzip', 'br'])
async def test_official_sdk_shares_preflight_and_retains_receipts_after_close(
    monkeypatch, kind, signing_algo, encoding
):
    gateway = DecisionGateway(signing_algo, kind)
    gateway.response_encoding = encoding
    gateway.body_id = 'not-the-receipt-id'
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        async with official_client(client) as jev:
            first, second = await asyncio.gather(decision(jev), decision(jev))
            assert first.nouls['useful'].noul == 0.9
            assert first.choices['action'].choice == 'keep'
            assert first.scores['quality'].score == 1
            first.answers.clear()  # Parsed data is separate from signed bytes.
        for result in (first, second):
            response = result.raw_http_response
            assert 'content-encoding' not in response.headers
            assert int(response.headers['content-length']) == len(response.content)
            receipt_id = response.headers['x-generation-id']
            verified = await client.verify_response(receipt_id)
            assert verified.id == receipt_id
            assert verified.signature_kind == kind
        with pytest.raises(ApiError):
            await client.verify_response('not-the-receipt-id')
        # Closing the official client closes only its borrowed adapter.
        third = await client.systemone.create(REQUEST)
        await client.verify_response(third.decision_id)
    assert gateway.gateway_requests == 1
    assert len(gateway.requests) == 3
    for request in gateway.requests:
        assert request.headers['authorization'] == 'Bearer test-key'
        assert request.headers['x-no-aliasing'] == 'true'
        assert request.headers['accept-encoding'] == 'identity'
        assert request.headers.get('x-model-pub-key') == (
            gateway.public_key if kind == 'provider_tee' else None
        )
        assert 'x-client-pub-key' not in request.headers


@pytest.mark.parametrize('fault', ['tamper', 'signer'])
async def test_official_sdk_receipt_rejects_changed_bytes_or_another_signer(
    monkeypatch, fault
):
    gateway = DecisionGateway(kind='provider_tee')
    gateway.response_encoding = 'br'
    gateway.response_fault = 'tamper' if fault == 'tamper' else None
    gateway.use_alternate_signer = fault == 'signer'
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client, official_client(client) as jev:
        result = await decision(jev)
        with pytest.raises(VerificationError):
            await client.verify_response(
                result.raw_http_response.headers['x-generation-id']
            )
    assert len(gateway.requests) == 1


@pytest.mark.parametrize('fault', ['status', 'id'])
async def test_official_sdk_does_not_retry_failed_decisions(monkeypatch, fault):
    gateway = DecisionGateway()
    gateway.response_fault = fault
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client, official_client(client) as jev:
        with pytest.raises(ApiError):
            await decision(jev)
        with pytest.raises(ApiError) as missing:
            await client.verify_response('systemone-1')
        assert missing.value.failure.code == 'api.completion_not_found'
    assert len(gateway.requests) == 1
    assert gateway.signature_requests == 0


@pytest.mark.parametrize('option', ['e2ee', 'ohttp'])
async def test_official_sdk_rejects_encryption_before_preflight(monkeypatch, option):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    options = {'e2ee': False, option: True}
    async with gateway.client(**options) as client, official_client(client) as jev:
        with pytest.raises(ApiError) as raised:
            await decision(jev)
        assert raised.value.failure.code == 'api.invalid_input'
    assert gateway.headers == []


async def test_official_sdk_does_not_send_on_failed_preflight(monkeypatch):
    gateway = DecisionGateway(kind='provider_tee')
    gateway.omit_public_key = True
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client, official_client(client) as jev:
        with pytest.raises(VerificationError) as raised:
            await decision(jev)
        assert raised.value.failure.code == 'e2ee.model_public_key_required'
    assert gateway.requests == []
