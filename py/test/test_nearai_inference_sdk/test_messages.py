"""Messages creation and exact Gateway receipts, including native SSE shapes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest
from anthropic import APIStatusError, AsyncAnthropic
from eth_account.messages import encode_defunct

from nearai_inference_sdk import ApiError, DirectInferenceClient, VerificationError

from .ohttp_fixtures import OhttpGateway
from .test_inference_client import BASE_URL, MODEL, ChunkStream, Gateway

FIXTURES = Path(__file__).resolve().parents[3] / 'test-fixtures' / 'messages'
ERROR_HEADER_ENDING = b'event: error\ndata: {"type":"message_stop"}\n\n'


class MessagesGateway(Gateway):
    def __init__(self, *, streaming=False, ohttp=False, **kwargs):
        super().__init__(kind='gateway', **kwargs)
        self.metadata = {'providerType': 'anthropic', 'attestationSupported': False}
        self.streaming = streaming
        self.oblivious = OhttpGateway(handler=self.handle_inner) if ohttp else None
        self.outer_requests = 0
        self.tamper = False
        self.missing_id = False
        self.retry_signature = False
        self.status = 200
        self.raw = (
            FIXTURES / ('message.sse' if streaming else 'message.json')
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
        if request.url.path != '/v1/messages':
            return await super().handle(request)
        assert self.gateway_requests > 0
        assert request.headers['authorization'] == 'Bearer test-key'
        assert request.headers['x-no-aliasing'] == 'true'
        assert 'x-client-pub-key' not in request.headers
        assert 'x-model-pub-key' not in request.headers
        assert 'x-api-key' not in request.headers
        assert request.headers['anthropic-version']
        self.completion_requests.append(request)
        text = f'{hashlib.sha256(request.content).hexdigest()}:{hashlib.sha256(self.raw).hexdigest()}'
        if self.kind == 'provider_tee':
            text = f'{MODEL}:{text}'
        signature = (
            self.key.sign(text.encode()).signature.hex()
            if self.signing_algo == 'ed25519'
            else self.key.sign_message(encode_defunct(text=text)).signature.hex()
        )
        self.signatures['msg_fixture'] = {
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
async def test_messages_wire_receipts(
    monkeypatch, streaming, ohttp, external, signing_algo
):
    gateway = MessagesGateway(
        streaming=streaming, ohttp=ohttp, signing_algo=signing_algo
    )
    if ohttp:
        gateway.metadata = {'providerType': 'openai', 'attestationSupported': False}
    gateway.install(monkeypatch)
    input_items = [
        {
            'role': 'assistant',
            'content': [
                {'type': 'tool_use', 'id': 'prior', 'name': 'weather', 'input': {}}
            ],
        },
        {
            'role': 'user',
            'content': [
                {
                    'type': 'tool_result',
                    'tool_use_id': 'prior',
                    'content': '{"temperature":20}',
                }
            ],
        },
    ]
    async with gateway.client(e2ee=False, ohttp=ohttp) as client:
        wrapped = (
            AsyncAnthropic(
                api_key='external',
                max_retries=0,
                base_url=BASE_URL.removesuffix('v1/'),
                http_client=client.http_client,
            )
            if external
            else None
        )
        messages = wrapped.messages if wrapped else client.messages
        try:
            result = await messages.create(
                model=MODEL, messages=input_items, max_tokens=128, stream=streaming
            )
            if streaming:
                events = [event async for event in result]
                assert events[0].message.id == 'msg_fixture'
                assert events[-1].type == 'message_stop'
                assert any(event.type == 'content_block_delta' for event in events)
            else:
                assert result.id == 'msg_fixture'
                assert result.content[1].input == {'city': '北京'}
            receipt = await client.verify_response('msg_fixture')
            assert receipt.signature_kind == 'gateway'
            assert receipt.signature.signed_text.endswith(
                hashlib.sha256(gateway.raw).hexdigest()
            )
            assert (
                json.loads(gateway.completion_requests[0].content)['messages']
                == input_items
            )
            assert len(gateway.completion_requests) == 1
            assert gateway.outer_requests == int(ohttp)
            with pytest.raises(ApiError, match='api.completion_not_found'):
                await client.verify_response('toolu_fixture')
        finally:
            if wrapped:
                await wrapped.close()


@pytest.mark.parametrize('streaming', [False, True])
async def test_messages_tamper(monkeypatch, streaming):
    gateway = MessagesGateway(streaming=streaming)
    gateway.tamper = True
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        response = await client.send(
            httpx.Request(
                'POST', BASE_URL + 'messages', json={'model': MODEL, 'input': 'Hi'}
            )
        )
        await response.aread()
        with pytest.raises(VerificationError, match='signature.payload_mismatch'):
            await client.verify_response('msg_fixture')


async def test_messages_require_gateway_receipt(monkeypatch):
    gateway = MessagesGateway()
    gateway.kind = 'provider_tee'
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        await client.messages.create(
            model=MODEL, messages=[{'role': 'user', 'content': 'Hi'}], max_tokens=128
        )
        with pytest.raises(VerificationError, match='signature.kind_mismatch'):
            await client.verify_response('msg_fixture')


@pytest.mark.parametrize('httpx2', [False, True])
async def test_messages_retry_receipt_only(monkeypatch, httpx2):
    gateway = MessagesGateway()
    gateway.retry_signature = True
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        if httpx2:
            async with client.httpx2_client as adapter:
                response = await adapter.post(
                    BASE_URL + 'messages', json={'model': MODEL, 'input': 'Hi'}
                )
            assert response.json()['id'] == 'msg_fixture'
        else:
            await client.messages.create(
                model=MODEL,
                messages=[{'role': 'user', 'content': 'Hi'}],
                max_tokens=128,
            )
        with pytest.raises(ApiError, match='api.http_status'):
            await client.verify_response('msg_fixture')
        assert (await client.verify_response('msg_fixture')).signature_kind == 'gateway'
        assert len(gateway.completion_requests) == 1


@pytest.mark.parametrize('streaming', [False, True])
async def test_messages_missing_id(monkeypatch, streaming):
    gateway = MessagesGateway(streaming=streaming)
    gateway.missing_id = True
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        response = await client.send(
            httpx.Request(
                'POST', BASE_URL + 'messages', json={'model': MODEL, 'input': 'Hi'}
            )
        )
        with pytest.raises(ApiError, match='api.invalid_response'):
            await response.aread()


async def test_messages_http_error(monkeypatch):
    gateway = MessagesGateway()
    gateway.status = 400
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        response = await client.send(
            httpx.Request(
                'POST', BASE_URL + 'messages', json={'model': MODEL, 'input': 'Hi'}
            )
        )
        assert response.status_code == 400
        await response.aclose()
        with pytest.raises(ApiError, match='api.completion_not_found'):
            await client.verify_response('msg_fixture')


async def test_messages_reject_unsupported_paths_and_e2ee_before_io(monkeypatch):
    gateway = MessagesGateway()
    gateway.install(monkeypatch)
    async with (
        gateway.client(e2ee=True) as encrypted,
        gateway.client(e2ee=False) as plain,
        DirectInferenceClient(base_url=BASE_URL, e2ee=False) as direct,
    ):
        for client, url in [
            (encrypted, BASE_URL + 'messages'),
            (direct, BASE_URL + 'messages'),
            (plain, BASE_URL + 'messages/msg_fixture'),
            (plain, 'https://other.test/v1/messages'),
        ]:
            with pytest.raises(ApiError, match='api.invalid_input'):
                await client.send(
                    httpx.Request('POST', url, json={'model': MODEL, 'input': 'Hi'})
                )
    assert gateway.gateway_requests == 0
    assert not gateway.completion_requests


@pytest.mark.parametrize(
    'ending',
    [
        ERROR_HEADER_ENDING,
        b'event:error\ndata: {"error":{"type":"overloaded_error"}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n',
        b'event: ping\r\ndata: {"type":"message_stop"}\r\n\r\n',
        b'',
        b'event: message_stop\ndata: {"type":"message_stop"}',
        b'event: error\ndata: {"type":"error","error":{"type":"overloaded_error"}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n',
        b'event: message_start\ndata: {"type":"message_start","message":{"id":"other"}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n',
    ],
)
async def test_messages_incomplete_or_failed_stream(monkeypatch, ending):
    gateway = MessagesGateway(streaming=True)
    gateway.raw = (
        b'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_fixture"}}\n\n'
        + ending
    )
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        response = await client.send(
            httpx.Request('POST', BASE_URL + 'messages', json={'model': MODEL})
        )
        with pytest.raises(ApiError, match='api.invalid_response'):
            await response.aread()
        with pytest.raises(ApiError, match='api.invalid_response'):
            await client.verify_response('msg_fixture')
    assert len(gateway.completion_requests) == 1


async def test_messages_cannot_verify_after_sdk_rejects_error_header(monkeypatch):
    gateway = MessagesGateway(streaming=True)
    gateway.raw = (
        b'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_fixture"}}\n\n'
        + ERROR_HEADER_ENDING
    )
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        stream = await client.messages.create(
            model=MODEL,
            max_tokens=16,
            messages=[{'role': 'user', 'content': 'Hello'}],
            stream=True,
        )
        with pytest.raises(APIStatusError):
            async with stream:
                async for event in stream:
                    assert event.type == 'message_start'
        with pytest.raises(ApiError, match='api.invalid_response'):
            await client.verify_response('msg_fixture')
    assert not gateway.signature_requests
    assert len(gateway.completion_requests) == 1


async def test_messages_close_before_completion(monkeypatch):
    gateway = MessagesGateway(streaming=True)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        response = await client.send(
            httpx.Request('POST', BASE_URL + 'messages', json={'model': MODEL})
        )
        captured = b''
        async for chunk in response.aiter_bytes():
            captured += chunk
            if b'"output_tokens":0}}' in captured:
                break
        await response.aclose()
        with pytest.raises(ApiError):
            await client.verify_response('msg_fixture')
    assert len(gateway.completion_requests) == 1


async def test_messages_custom_prefix_and_protocol_headers(monkeypatch):
    from nearai_inference_sdk import InferenceClient

    requests = []

    async def send(self, request):
        requests.append(request)
        return httpx.Response(
            200,
            request=request,
            json={'id': 'msg_custom', 'type': 'message', 'content': []},
        )

    monkeypatch.setattr(InferenceClient, 'send', send)
    async with InferenceClient(
        'test',
        base_url='https://gateway.test/custom/api/',
        headers={'anthropic-version': '2026-10-21'},
    ) as client:
        args = {
            'model': MODEL,
            'max_tokens': 8,
            'messages': [{'role': 'user', 'content': 'Hello'}],
        }
        await client.messages.create(
            **args,
            extra_headers={
                'anthropic-version': '2023-06-01',
                'anthropic-beta': 'test-beta',
            },
        )
        await client.messages.create(**args)
    assert str(requests[0].url) == 'https://gateway.test/custom/api/messages'
    assert requests[0].headers['anthropic-beta'] == 'test-beta'
    assert requests[0].headers['anthropic-version'] == '2023-06-01'
    assert requests[1].headers['anthropic-version'] == '2026-10-21'


@pytest.mark.parametrize(
    'case',
    json.loads((FIXTURES / 'streams.json').read_text()),
    ids=lambda case: case['name'],
)
async def test_messages_stream_contract(monkeypatch, case):
    gateway = MessagesGateway(streaming=True)
    gateway.raw = case['body'].encode()
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:

        async def consume():
            response = await client.send(
                httpx.Request('POST', BASE_URL + 'messages', json={'model': MODEL})
            )
            return await response.aread()

        if case['valid']:
            assert await consume() == gateway.raw
            await client.verify_response('msg_fixture')
        else:
            with pytest.raises(ApiError):
                await consume()
            with pytest.raises(ApiError):
                await client.verify_response('msg_fixture')
            assert not gateway.signature_requests
    assert len(gateway.completion_requests) == 1
