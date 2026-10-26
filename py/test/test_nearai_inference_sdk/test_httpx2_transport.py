"""HTTPX and HTTPX2 adapters share the verified request pipeline."""

import asyncio
import gzip
import json
import subprocess
import sys

import httpx
import httpx2
import pytest
from openai import AsyncOpenAI

from nearai_inference_sdk import ApiError, VerificationError

from .test_inference_client import BASE_URL, MESSAGES, MODEL, ChunkStream, Gateway
from .test_inference_ohttp import ObliviousGateway
from .test_systemone import REQUEST, DecisionGateway


@pytest.mark.parametrize('adapter_name', ['http_client', 'httpx2_client'])
@pytest.mark.parametrize('e2ee', [False, True])
@pytest.mark.parametrize('kind', ['gateway', 'provider_tee'])
@pytest.mark.parametrize('mode', ['ed25519', 'ecdsa', 'ohttp'])
async def test_openai_json_and_sse_share_verification(
    monkeypatch, adapter_name, e2ee, kind, mode
):
    gateway = ObliviousGateway(kind) if mode == 'ohttp' else Gateway(mode, kind)
    gateway.install(monkeypatch)
    async with (
        gateway.client(e2ee=e2ee) as owner,
        AsyncOpenAI(
            api_key='external-key',
            base_url=owner.base_url,
            http_client=getattr(owner, adapter_name),
        ) as openai,
    ):
        completion = await openai.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        assert completion.choices[0].message.content == 'Hello back'
        assert (await owner.verify_response(completion.id)).signature_kind == kind
        async with await openai.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        ) as stream:
            chunks = [chunk async for chunk in stream]
        assert chunks[0].choices[0].delta.content == 'Hello back'
        assert (await owner.verify_response(chunks[0].id)).signature_kind == kind
    assert gateway.gateway_requests == 1
    assert gateway.model_requests == [MODEL]
    assert gateway.signature_requests == 2
    assert gateway.plaintexts == ['Hello', 'Hello']
    assert all(
        ('Hello' not in request.content.decode()) == e2ee
        for request in gateway.completion_requests
    )


@pytest.mark.parametrize('adapter_name', ['http_client', 'httpx2_client'])
async def test_failed_preflight_preserves_sdk_error(monkeypatch, adapter_name):
    gateway = Gateway()
    gateway.bad_quote = True
    gateway.install(monkeypatch)
    async with gateway.client() as owner, getattr(owner, adapter_name) as adapter:
        with pytest.raises(VerificationError) as raised:
            await adapter.post(
                BASE_URL + 'chat/completions',
                json={'model': MODEL, 'messages': MESSAGES},
            )
    assert raised.value.failure.code == 'policy.debug_enabled'
    assert gateway.completion_requests == []


@pytest.mark.parametrize('adapter_name', ['http_client', 'httpx2_client'])
@pytest.mark.parametrize('finish', ['cancel', 'timeout'])
async def test_stream_failure_closes_source_and_cannot_verify(
    monkeypatch, adapter_name, finish
):
    gateway = Gateway()
    handle = gateway.handle
    reading = asyncio.Event()
    closed = asyncio.Event()

    class FailingStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"id":"incomplete"}\n\n'
            if finish == 'timeout':
                raise httpx.ReadTimeout('stalled response')
            reading.set()
            await asyncio.Event().wait()

        async def aclose(self):
            closed.set()

    async def fail_chat(request):
        if request.url.path.endswith('/chat/completions'):
            return httpx.Response(
                200,
                headers={'content-type': 'text/event-stream'},
                stream=FailingStream(),
            )
        return await handle(request)

    monkeypatch.setattr(gateway, 'handle', fail_chat)
    gateway.install(monkeypatch)
    backend = httpx if adapter_name == 'http_client' else httpx2
    async with (
        gateway.client(e2ee=False) as owner,
        getattr(owner, adapter_name) as adapter,
    ):
        request = adapter.build_request(
            'POST',
            BASE_URL + 'chat/completions',
            json={'model': MODEL, 'messages': MESSAGES, 'stream': True},
        )
        response = await adapter.send(request, stream=True)
        try:
            chunks = response.aiter_bytes()
            assert await anext(chunks) == b'data: {"id":"incomplete"}\n\n'
            if finish == 'cancel':
                task = asyncio.create_task(anext(chunks))
                await asyncio.wait_for(reading.wait(), timeout=2)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                with pytest.raises(backend.ReadTimeout) as raised:
                    await anext(chunks)
                assert raised.value.request is request
            await asyncio.wait_for(closed.wait(), timeout=2)
            with pytest.raises(ApiError):
                await owner.verify_response('incomplete')
        finally:
            await response.aclose()
    assert gateway.signature_requests == 0


@pytest.mark.parametrize('buffered', [False, True])
async def test_error_response_preserves_status_headers_and_decodes_once(
    monkeypatch, buffered
):
    gateway = Gateway()
    handle = gateway.handle
    payload = b'{"error":{"message":"busy","type":"overloaded"}}'
    compressed = gzip.compress(payload)

    async def reject_chat(request):
        if request.url.path.endswith('/chat/completions'):
            return httpx.Response(
                429,
                headers=[
                    ('content-encoding', 'gzip'),
                    ('content-type', 'application/json'),
                    ('retry-after', '3'),
                    ('x-probe', 'a'),
                    ('x-probe', 'b'),
                ],
                **(
                    {'content': compressed}
                    if buffered
                    else {'stream': ChunkStream([compressed])}
                ),
            )
        return await handle(request)

    monkeypatch.setattr(gateway, 'handle', reject_chat)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as owner, owner.httpx2_client as adapter:
        response = await adapter.post(
            BASE_URL + 'chat/completions', json={'model': MODEL, 'messages': MESSAGES}
        )
        assert response.status_code == 429
        assert response.content == payload
        assert response.headers['retry-after'] == '3'
        assert response.headers.get_list('x-probe') == ['a', 'b']
        with pytest.raises(httpx2.HTTPStatusError):
            response.raise_for_status()


@pytest.mark.parametrize('kind', ['gateway', 'provider_tee'])
@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
async def test_bridge_preserves_bytes_query_headers_and_timeouts(
    monkeypatch, kind, signing_algo
):
    gateway = DecisionGateway(signing_algo, kind)
    gateway.install(monkeypatch)
    body = ('\n' + json.dumps(REQUEST, indent=2, ensure_ascii=False) + '\n').encode()
    url = BASE_URL + 'systemone?trace=a%2Fb&trace=%25&empty='
    timeout = httpx2.Timeout(3, read=7, write=5, pool=1)
    async with gateway.client(e2ee=False) as owner:
        async with owner.http_client as chat:
            assert isinstance(chat, httpx.AsyncClient)
            assert not isinstance(chat, httpx2.AsyncClient)
        async with owner.httpx2_client as adapter:
            response = await adapter.post(
                url,
                content=body,
                headers=[
                    ('content-type', 'application/json'),
                    ('x-probe', 'first'),
                    ('x-probe', 'second'),
                ],
                timeout=timeout,
            )
            assert isinstance(response, httpx2.Response)
            verified = await owner.verify_response(response.headers['x-generation-id'])
            assert verified.signature_kind == kind
        sent = gateway.requests[0]
        assert isinstance(sent, httpx.Request)
        assert sent.content == body
        assert sent.headers['authorization'] == 'Bearer test-key'
        assert sent.headers.get('x-model-pub-key') == (
            gateway.public_key if kind == 'provider_tee' else None
        )
        assert sent.url.raw_path == httpx2.URL(url).raw_path
        assert sent.headers.get_list('x-probe') == ['first', 'second']
        assert sent.extensions['timeout'] == timeout.as_dict()
        result = await owner.systemone.create(REQUEST)
        await owner.verify_response(result.decision_id)
    assert gateway.gateway_requests == 1
    assert len(gateway.requests) == 2


async def test_bridge_cancels_body_read_before_preflight(monkeypatch):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    started = asyncio.Event()
    closed = asyncio.Event()

    async def body():
        try:
            yield b'{'
            started.set()
            await asyncio.Event().wait()
        finally:
            closed.set()

    async with (
        gateway.client(e2ee=False) as owner,
        owner.httpx2_client as adapter,
    ):
        request = httpx2.Request(
            'POST',
            BASE_URL + 'systemone',
            content=body(),
            headers={'content-type': 'application/json'},
        )
        task = asyncio.create_task(adapter.send(request))
        await asyncio.wait_for(started.wait(), timeout=2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
    assert closed.is_set()
    assert gateway.headers == []


@pytest.mark.parametrize(
    'method,url,headers,body',
    [
        ('GET', BASE_URL + 'systemone', {}, b'{}'),
        ('POST', 'https://other.test/v1/systemone', {}, b'{}'),
        ('POST', BASE_URL + 'responses', {}, b'{}'),
        (
            'POST',
            BASE_URL + 'systemone',
            {'content-type': 'multipart/form-data'},
            b'{}',
        ),
        (
            'POST',
            BASE_URL + 'systemone',
            {'content-type': 'application/json', 'content-encoding': 'zstd'},
            b'compressed',
        ),
        ('POST', BASE_URL + 'systemone', {'content-type': 'application/json'}, b'{'),
        (
            'POST',
            BASE_URL + 'systemone',
            {'content-type': 'application/json'},
            b'{"model":"test-model","stream":false}',
        ),
    ],
)
async def test_raw_systemone_rejects_unsupported_input_before_io(
    monkeypatch, method, url, headers, body
):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    async with (
        gateway.client(e2ee=False) as client,
        client.httpx2_client as adapter,
    ):
        with pytest.raises(ApiError) as raised:
            await adapter.send(
                httpx2.Request(method, url, headers=headers, content=body)
            )
        assert raised.value.failure.code == 'api.invalid_input'
    assert gateway.headers == []


async def test_raw_systemone_rejects_configured_compression(monkeypatch):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)

    async with (
        gateway.client(e2ee=False, headers={'content-encoding': 'gzip'}) as client,
        client.httpx2_client as adapter,
    ):
        with pytest.raises(ApiError) as raised:
            await adapter.send(
                httpx2.Request('POST', BASE_URL + 'systemone', json=REQUEST)
            )

    assert raised.value.failure.code == 'api.invalid_input'
    assert gateway.headers == []


@pytest.mark.parametrize('fault', ['status', 'id'])
async def test_bridge_propagates_failure_without_retry(monkeypatch, fault):
    gateway = DecisionGateway()
    gateway.response_fault = fault
    gateway.install(monkeypatch)
    async with (
        gateway.client(e2ee=False) as owner,
        owner.httpx2_client as adapter,
    ):
        with pytest.raises(ApiError):
            await adapter.post(BASE_URL + 'systemone', json=REQUEST)
        with pytest.raises(ApiError) as missing:
            await owner.verify_response('systemone-1')
        assert missing.value.failure.code == 'api.completion_not_found'
    assert len(gateway.requests) == 1
    assert gateway.signature_requests == 0


def test_optional_dependencies_load_only_when_the_property_is_accessed():
    subprocess.run(
        [
            sys.executable,
            '-c',
            """
import asyncio
import sys
from importlib.abc import MetaPathFinder

class BlockOptionalDependencies(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'httpx2', 'typesafe_sdk'}:
            raise ImportError(f'Optional dependency unexpectedly imported: {fullname}')

blocker = BlockOptionalDependencies()
sys.meta_path.insert(0, blocker)
import httpx
from openai import AsyncOpenAI
from nearai_inference_sdk import InferenceClient

async def main():
    async with InferenceClient('test-key') as owner:
        async with AsyncOpenAI(api_key='test-key', http_client=owner.http_client) as ai:
            assert isinstance(ai._client, httpx.AsyncClient)
            assert owner.chat is not None
        assert 'httpx2' not in sys.modules
        assert 'nearai_inference_sdk.integrations.httpx2' not in sys.modules
        sys.meta_path.remove(blocker)
        async with owner.httpx2_client as adapter:
            import httpx2
            assert isinstance(adapter, httpx2.AsyncClient)
        async with owner.httpx2_client as other:
            assert other is not adapter
            assert not other.is_closed
        assert 'typesafe_sdk' not in sys.modules

asyncio.run(main())
""",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
