"""Responses creation and exact Gateway receipts, including native SSE shapes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest
from eth_account.messages import encode_defunct
from openai import AsyncOpenAI

from nearai_inference_sdk import ApiError, DirectInferenceClient, VerificationError

from .ohttp_fixtures import OhttpGateway
from .test_inference_client import BASE_URL, MODEL, ChunkStream, Gateway

FIXTURES = Path(__file__).resolve().parents[3] / 'test-fixtures' / 'responses'


class ResponsesGateway(Gateway):
    def __init__(self, *, streaming=False, ohttp=False, **kwargs):
        super().__init__(kind='gateway', **kwargs)
        self.streaming = streaming
        self.oblivious = OhttpGateway(handler=self.handle_inner) if ohttp else None
        self.outer_requests = 0
        self.tamper = False
        self.missing_id = False
        self.retry_signature = False
        self.status = 200
        self.raw = (
            FIXTURES / ('response.sse' if streaming else 'response.json')
        ).read_bytes()

    async def handle(self, request):
        if request.url.path == '/ohttp':
            self.outer_requests += 1
            return await self.oblivious.handle(request)
        if request.url.path.startswith('/v1/signature/') and self.retry_signature:
            self.retry_signature = False
            return httpx.Response(503)
        response = await self.handle_inner(request)
        if self.oblivious and request.url.path == '/v1/attestation/report':
            config = self.oblivious.key_config
            value = response.json()
            value['ohttp_attestation'] = {
                'signing_algo': 'ed25519',
                'signing_key': self.public_key,
                'key_config': config.hex(),
                'signature': self.key.sign(config).signature.hex(),
            }
            return httpx.Response(200, json=value)
        return response

    async def handle_inner(self, request):
        if request.url.path != '/v1/responses':
            return await super().handle(request)
        assert self.gateway_requests > 0
        assert request.headers['authorization'] == 'Bearer test-key'
        assert request.headers['x-no-aliasing'] == 'true'
        assert 'x-client-pub-key' not in request.headers
        self.completion_requests.append(request)
        text = f'{hashlib.sha256(request.content).hexdigest()}:{hashlib.sha256(self.raw).hexdigest()}'
        if self.kind == 'provider_tee':
            text = f'{MODEL}:{text}'
        signature = (
            self.key.sign(text.encode()).signature.hex()
            if self.signing_algo == 'ed25519'
            else self.key.sign_message(encode_defunct(text=text)).signature.hex()
        )
        self.signatures['resp_fixture'] = {
            'text': text,
            'signature': signature,
            'signing_algo': self.signing_algo,
            'signing_address': self.address,
            'signature_kind': self.kind,
        }
        visible = (
            self.raw.replace('你好'.encode(), '篡改'.encode())
            if self.tamper
            else self.raw
        )
        if self.missing_id:
            visible = (
                b'data: {"id":"item-only","item":{"id":"msg_1"}}\n\n'
                if self.streaming
                else b'{"output":[]}'
            )
        return httpx.Response(
            self.status,
            headers={
                'content-type': 'text/event-stream'
                if self.streaming
                else 'application/json'
            },
            stream=ChunkStream([visible[i : i + 7] for i in range(0, len(visible), 7)]),
        )


@pytest.mark.parametrize(
    'streaming,ohttp,external,signing_algo',
    [
        (False, False, False, 'ed25519'),
        (True, False, True, 'ecdsa'),
        (False, True, True, 'ed25519'),
        (True, True, False, 'ed25519'),
    ],
)
async def test_responses_wire_receipts(
    monkeypatch, streaming, ohttp, external, signing_algo
):
    gateway = ResponsesGateway(
        streaming=streaming, ohttp=ohttp, signing_algo=signing_algo
    )
    if ohttp:
        gateway.metadata = {'providerType': 'openai', 'attestationSupported': False}
    gateway.install(monkeypatch)
    input_items = [
        {
            'type': 'function_call',
            'call_id': 'prior',
            'name': 'weather',
            'arguments': '{}',
        },
        {
            'type': 'function_call_output',
            'call_id': 'prior',
            'output': '{"temperature":20}',
        },
    ]
    async with gateway.client(e2ee=False, ohttp=ohttp) as client:
        wrapped = (
            AsyncOpenAI(
                api_key='external', base_url=BASE_URL, http_client=client.http_client
            )
            if external
            else None
        )
        responses = wrapped.responses if wrapped else client.responses
        try:
            result = await responses.create(
                model=MODEL, input=input_items, store=False, stream=streaming
            )
            if streaming:
                events = [event async for event in result]
                assert events[-1].response.id == 'resp_fixture'
                assert any(
                    event.type == 'response.function_call_arguments.delta'
                    for event in events
                )
            else:
                assert result.id == 'resp_fixture'
                assert result.output[2].arguments == '{"city":"北京"}'
            receipt = await client.verify_response('resp_fixture')
            assert receipt.signature_kind == 'gateway'
            assert receipt.signature.signed_text.endswith(
                hashlib.sha256(gateway.raw).hexdigest()
            )
            assert (
                json.loads(gateway.completion_requests[0].content)['input']
                == input_items
            )
            assert len(gateway.completion_requests) == 1
            assert gateway.outer_requests == int(ohttp)
            with pytest.raises(ApiError, match='api.completion_not_found'):
                await client.verify_response('msg_1')
        finally:
            if wrapped:
                await wrapped.close()


@pytest.mark.parametrize('streaming', [False, True])
@pytest.mark.parametrize('limit', ['max_body_bytes', 'max_receipt_cache_bytes'])
async def test_responses_capacity_limits(monkeypatch, streaming, limit):
    gateway = ResponsesGateway(streaming=streaming)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False, **{limit: 512}) as client:
        response = await client.send(
            httpx.Request(
                'POST', BASE_URL + 'responses', json={'model': MODEL, 'input': 'Hi'}
            )
        )
        with pytest.raises(ApiError, match='api.body_too_large'):
            await response.aread()
    assert len(gateway.completion_requests) == 1


@pytest.mark.parametrize('streaming', [False, True])
async def test_responses_tamper(monkeypatch, streaming):
    gateway = ResponsesGateway(streaming=streaming)
    gateway.tamper = True
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        response = await client.send(
            httpx.Request(
                'POST', BASE_URL + 'responses', json={'model': MODEL, 'input': 'Hi'}
            )
        )
        await response.aread()
        with pytest.raises(VerificationError, match='signature.payload_mismatch'):
            await client.verify_response('resp_fixture')


async def test_responses_require_gateway_receipt(monkeypatch):
    gateway = ResponsesGateway()
    gateway.kind = 'provider_tee'
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        await client.responses.create(model=MODEL, input='Hi')
        with pytest.raises(VerificationError, match='signature.kind_mismatch'):
            await client.verify_response('resp_fixture')


@pytest.mark.parametrize('httpx2', [False, True])
async def test_responses_retry_receipt_only(monkeypatch, httpx2):
    gateway = ResponsesGateway()
    gateway.retry_signature = True
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        if httpx2:
            async with client.httpx2_client as adapter:
                response = await adapter.post(
                    BASE_URL + 'responses', json={'model': MODEL, 'input': 'Hi'}
                )
            assert response.json()['id'] == 'resp_fixture'
        else:
            await client.responses.create(model=MODEL, input='Hi')
        with pytest.raises(ApiError, match='api.http_status'):
            await client.verify_response('resp_fixture')
        assert (
            await client.verify_response('resp_fixture')
        ).signature_kind == 'gateway'
        assert len(gateway.completion_requests) == 1


@pytest.mark.parametrize('streaming', [False, True])
async def test_responses_missing_id(monkeypatch, streaming):
    gateway = ResponsesGateway(streaming=streaming)
    gateway.missing_id = True
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        response = await client.send(
            httpx.Request(
                'POST', BASE_URL + 'responses', json={'model': MODEL, 'input': 'Hi'}
            )
        )
        with pytest.raises(ApiError, match='api.invalid_response'):
            await response.aread()


async def test_responses_http_error(monkeypatch):
    gateway = ResponsesGateway()
    gateway.status = 400
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        response = await client.send(
            httpx.Request(
                'POST', BASE_URL + 'responses', json={'model': MODEL, 'input': 'Hi'}
            )
        )
        assert response.status_code == 400
        await response.aclose()
        with pytest.raises(ApiError, match='api.completion_not_found'):
            await client.verify_response('resp_fixture')


async def test_responses_reject_unsupported_paths_and_e2ee_before_io(monkeypatch):
    gateway = ResponsesGateway()
    gateway.install(monkeypatch)
    async with (
        gateway.client(e2ee=True) as encrypted,
        gateway.client(e2ee=False) as plain,
        DirectInferenceClient(base_url=BASE_URL, e2ee=False) as direct,
    ):
        for client, url in [
            (encrypted, BASE_URL + 'responses'),
            (direct, BASE_URL + 'responses'),
            (plain, BASE_URL + 'responses/resp_fixture'),
            (plain, 'https://other.test/v1/responses'),
        ]:
            with pytest.raises(ApiError, match='api.invalid_input'):
                await client.send(
                    httpx.Request('POST', url, json={'model': MODEL, 'input': 'Hi'})
                )
    assert gateway.gateway_requests == 0
    assert not gateway.completion_requests
