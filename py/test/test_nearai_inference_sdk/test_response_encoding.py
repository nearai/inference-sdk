"""Reject compressed inference bodies before HTTPX can expand their contents."""

import gzip

import httpx
import pytest

from nearai_inference_sdk import ApiError

from .test_inference_client import BASE_URL, MESSAGES, MODEL, Gateway
from .test_inference_ohttp import ObliviousGateway
from .test_systemone import REQUEST, DecisionGateway


@pytest.fixture(scope='module')
def compressed_body():
    # One small wire chunk expands well beyond the configured 1 MiB budget.
    body = gzip.compress(b'x' * (16 * 1024 * 1024))
    assert len(body) < 1024 * 1024
    return body


@pytest.mark.parametrize(
    'scenario',
    ['chat-json', 'chat-sse', 'chat-error', 'chat-e2ee', 'chat-ohttp', 'systemone'],
)
async def test_compressed_inference_response_is_closed_without_reading(
    monkeypatch, compressed_body, scenario
):
    gateway = (
        DecisionGateway()
        if scenario == 'systemone'
        else ObliviousGateway()
        if scenario == 'chat-ohttp'
        else Gateway()
    )
    original = gateway.handle
    consumed = 0
    closed = False
    sent = []

    class CompressedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            nonlocal consumed
            consumed += 1
            yield compressed_body

        async def aclose(self):
            nonlocal closed
            closed = True

    async def respond(request):
        if request.url.path in ('/v1/chat/completions', '/v1/systemone', '/ohttp'):
            sent.append(request)
            return httpx.Response(
                400 if scenario == 'chat-error' else 200,
                headers={
                    'content-encoding': 'gzip',
                    'content-type': 'message/ohttp-chunked-res'
                    if scenario == 'chat-ohttp'
                    else 'text/event-stream'
                    if scenario == 'chat-sse'
                    else 'application/json',
                    'x-generation-id': 'compressed',
                },
                stream=CompressedStream(),
            )
        return await original(request)

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(
        e2ee=scenario == 'chat-e2ee', max_body_bytes=1024 * 1024
    ) as client:
        with pytest.raises(ApiError) as failure:
            if scenario == 'systemone':
                await client.systemone.create(
                    REQUEST, headers={'accept-encoding': 'gzip, br'}
                )
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
                        headers={'accept-encoding': 'gzip, br'},
                    )
                )
                await response.aread()
        assert failure.value.failure.code == 'api.invalid_response'
        assert (
            failure.value.failure.details['path'] == 'response.headers.content-encoding'
        )
        assert not client._responses
    assert consumed == 0
    assert closed
    assert len(sent) == 1
    assert sent[0].headers['accept-encoding'] == 'identity'


@pytest.mark.parametrize(
    'encoding', ['br', 'deflate', 'zstd', 'identity, gzip', 'custom']
)
async def test_rejects_other_content_encodings_before_stream_iteration(
    monkeypatch, encoding
):
    gateway = Gateway()
    original = gateway.handle
    closed = False

    class UnreadableStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            pytest.fail('encoded response must not be consumed')
            yield b''

        async def aclose(self):
            nonlocal closed
            closed = True

    async def respond(request):
        if request.url.path == '/v1/chat/completions':
            return httpx.Response(
                200, headers={'content-encoding': encoding}, stream=UnreadableStream()
            )
        return await original(request)

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(ApiError, match='api.invalid_response'):
            response = await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
            await response.aread()
    assert closed


@pytest.mark.parametrize('encoding', [None, 'identity', 'IDENTITY'])
@pytest.mark.parametrize('endpoint', ['chat', 'systemone'])
async def test_identity_responses_preserve_exact_receipt_bytes(
    monkeypatch, encoding, endpoint
):
    gateway = DecisionGateway() if endpoint == 'systemone' else Gateway()
    original = gateway.handle
    sent = []

    async def respond(request):
        response = await original(request)
        if request.url.path in ('/v1/chat/completions', '/v1/systemone'):
            sent.append(request)
            if encoding is not None:
                response.headers['content-encoding'] = encoding
        return response

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        if endpoint == 'systemone':
            result = await client.systemone.create(
                REQUEST, headers={'accept-encoding': 'gzip, br'}
            )
            completion_id = result.decision_id
        else:
            result = await client.chat.completions.create(
                model=MODEL,
                messages=MESSAGES,
                extra_headers={'accept-encoding': 'gzip, br'},
            )
            completion_id = result.id
        verified = await client.verify_response(completion_id)
        assert verified.id == completion_id
    assert len(sent) == 1
    assert sent[0].headers['accept-encoding'] == 'identity'
