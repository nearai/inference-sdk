"""Apply body limits and receipt verification to decoded response bytes."""

import gzip

import brotli
import httpx
import pytest

from nearai_inference_sdk import ApiError

from .test_inference_client import BASE_URL, MESSAGES, MODEL, Gateway
from .test_inference_ohttp import ObliviousGateway
from .test_systemone import REQUEST, DecisionGateway


@pytest.mark.parametrize('encoding', ['gzip', 'br'])
@pytest.mark.parametrize(
    'scenario', ['chat-json', 'chat-sse', 'chat-error', 'systemone']
)
async def test_decoded_body_limit_closes_response_without_retaining_receipt(
    monkeypatch, encoding, scenario
):
    gateway = DecisionGateway() if scenario == 'systemone' else Gateway()
    handle = gateway.handle
    body = b'x' * 8192
    wire = gzip.compress(body) if encoding == 'gzip' else brotli.compress(body)
    assert len(wire) < 4096 < len(body)
    closed = False

    class CompressedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield wire

        async def aclose(self):
            nonlocal closed
            closed = True

    async def respond(request):
        if request.url.path in ('/v1/chat/completions', '/v1/systemone'):
            return httpx.Response(
                400 if scenario == 'chat-error' else 200,
                headers={
                    'content-encoding': encoding,
                    'content-type': 'text/event-stream'
                    if scenario == 'chat-sse'
                    else 'application/json',
                    'x-generation-id': 'compressed',
                },
                stream=CompressedStream(),
            )
        return await handle(request)

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False, max_body_bytes=4096) as client:
        with pytest.raises(ApiError, match='api.body_too_large'):
            if scenario == 'systemone':
                await client.systemone.create(REQUEST)
            else:
                response = await client.send(
                    httpx.Request(
                        'POST',
                        BASE_URL + 'chat/completions',
                        json={
                            'model': MODEL,
                            'messages': MESSAGES,
                            'stream': scenario == 'chat-sse',
                        },
                    )
                )
                await response.aread()
        assert not client._responses
    assert closed


@pytest.mark.parametrize('encoding', ['gzip', 'br'])
@pytest.mark.parametrize('transport', ['plain', 'e2ee', 'ohttp'])
async def test_compressed_chat_preserves_receipt_bytes(
    monkeypatch, encoding, transport
):
    gateway = ObliviousGateway() if transport == 'ohttp' else Gateway()
    handle = gateway.handle

    async def respond(request):
        response = await handle(request)
        if request.url.path not in ('/v1/chat/completions', '/ohttp'):
            return response
        body = await response.aread()
        wire = gzip.compress(body) if encoding == 'gzip' else brotli.compress(body)
        return httpx.Response(
            response.status_code,
            headers={
                **response.headers,
                'content-encoding': encoding,
                'content-length': str(len(wire)),
            },
            stream=httpx.ByteStream(wire),
        )

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=transport == 'e2ee') as client:
        result = await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        assert result.choices[0].message.content == 'Hello back'
        verified = await client.verify_response(result.id)
        assert verified.id == result.id
    assert len(gateway.completion_requests) == 1
