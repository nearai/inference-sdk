"""The optional Jev boundary preserves the verified HTTPX transport contract."""

import asyncio
import json
import subprocess
import sys

import httpx
import httpx2
import pytest

from nearai_inference_sdk import ApiError
from nearai_inference_sdk.integrations.jev import create_jev_http_client

from .test_inference_client import BASE_URL
from .test_systemone import REQUEST, DecisionGateway


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
        async with create_jev_http_client(owner) as adapter:
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
        create_jev_http_client(owner) as adapter,
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
        create_jev_http_client(client) as adapter,
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
        create_jev_http_client(client) as adapter,
    ):
        with pytest.raises(ApiError) as raised:
            await adapter.send(
                httpx2.Request('POST', BASE_URL + 'systemone', json=REQUEST)
            )

    assert raised.value.failure.code == 'api.invalid_input'
    assert gateway.headers == []


@pytest.mark.parametrize('fault', ['status', 'id', 'encoding'])
async def test_bridge_propagates_failure_without_retry(monkeypatch, fault):
    gateway = DecisionGateway()
    gateway.response_fault = fault
    gateway.install(monkeypatch)
    async with (
        gateway.client(e2ee=False) as owner,
        create_jev_http_client(owner) as adapter,
    ):
        with pytest.raises(ApiError):
            await adapter.post(BASE_URL + 'systemone', json=REQUEST)
        with pytest.raises(ApiError) as missing:
            await owner.verify_response('systemone-1')
        assert missing.value.failure.code == 'api.completion_not_found'
    assert len(gateway.requests) == 1
    assert gateway.signature_requests == 0


def test_openai_integration_does_not_import_optional_jev_dependencies():
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

sys.meta_path.insert(0, BlockOptionalDependencies())
import httpx
from openai import AsyncOpenAI
from nearai_inference_sdk import InferenceClient

async def main():
    async with InferenceClient('test-key') as owner:
        async with AsyncOpenAI(api_key='test-key', http_client=owner.http_client) as ai:
            assert isinstance(ai._client, httpx.AsyncClient)
            assert owner.chat is not None

asyncio.run(main())
assert 'httpx2' not in sys.modules
assert 'typesafe_sdk' not in sys.modules
""",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
