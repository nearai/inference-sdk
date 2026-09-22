from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest

from nearai_inference_sdk.core.ohttp import create_ohttp_client
from nearai_inference_sdk.utils.errors import (
    ApiError,
    VerificationError,
    verification_failure,
)

from .ohttp_fixtures import Chunks, OhttpGateway, varint, vector

BASE_URL = 'https://gateway.example/v1/'


@pytest.mark.parametrize('framing', [1, 3])
@pytest.mark.parametrize('fragment_size', [0, 1, 7])
async def test_json_roundtrip_preserves_exact_bytes_status_headers_and_private_fields(
    framing: int,
    fragment_size: int,
) -> None:
    gateway = OhttpGateway()
    gateway.response_status = 422
    gateway.response_headers = {
        'Content-Type': 'application/json',
        'X-Request-Id': 'signed-id',
    }
    gateway.response_framing = framing
    gateway.fragment_size = fragment_size
    body = b'{ "prompt": "private exact bytes", "padding": "' + b'x' * 33000 + b'" }'
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(gateway.handle)
    ) as outer:
        async with create_ohttp_client(
            gateway.key_config,
            base_url=BASE_URL,
            http_client=outer,
            forwarded_headers=[
                'X-Team',
                'CONTENT-TYPE',
                'x-client-pub-key',
                'Incremental',
            ],
        ) as client:
            response = await client.post(
                'chat/completions?test=%2F',
                content=body,
                headers={
                    'Authorization': 'Bearer key',
                    'X-Team': 'test-team',
                    'X-Private': 'private header',
                    'content-type': 'application/json',
                    'x-client-pub-key': 'private encryption key',
                    'Incremental': '?0',
                },
            )
        assert not outer.is_closed
    assert response.status_code == 422
    assert response.headers['content-type'] == 'application/json'
    assert response.headers['x-request-id'] == 'signed-id'
    assert response.content == gateway.response_body
    assert gateway.requests[0].content == body
    assert gateway.requests[0].url.raw_path == b'/v1/chat/completions?test=%2F'
    assert gateway.requests[0].headers['x-client-pub-key'] == 'private encryption key'
    assert gateway.requests[0].headers['incremental'] == '?0'
    request = gateway.outer_requests[0]
    assert str(request.url) == 'https://gateway.example/ohttp'
    assert request.headers['authorization'] == 'Bearer key'
    assert request.headers['x-team'] == 'test-team'
    assert request.headers.get_list('incremental') == ['?1']
    assert 'x-private' not in request.headers
    assert 'x-client-pub-key' not in request.headers
    assert b'private exact bytes' not in request.content
    assert gateway.streams[0].closed


async def test_custom_host_is_preserved_inside_the_encrypted_request() -> None:
    gateway = OhttpGateway()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(gateway.handle)
    ) as outer:
        async with create_ohttp_client(
            gateway.key_config, base_url=BASE_URL, http_client=outer
        ) as client:
            response = await client.get('models', headers={'Host': 'tenant.example'})

    assert response.status_code == 200
    assert gateway.requests[0].headers['host'] == 'tenant.example'
    assert gateway.requests[0].url.host == 'tenant.example'
    assert gateway.outer_requests[0].headers['host'] == 'gateway.example'
    assert gateway.outer_requests[0].url.host == 'gateway.example'


@pytest.mark.parametrize(
    'damage',
    [
        'truncate_final_response',
        'corrupt_final_response',
        'omit_final_response',
    ],
)
async def test_sse_done_does_not_skip_final_chunk_authentication(damage: str) -> None:
    gateway = OhttpGateway()
    gateway.response_headers = {'content-type': 'text/event-stream'}
    gateway.response_body = b'data: {"choices": []}\r\n\r\ndata: [DONE]\n\n'
    setattr(gateway, damage, True)
    seen = bytearray()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(gateway.handle)
    ) as outer:
        async with create_ohttp_client(
            gateway.key_config, base_url=BASE_URL, http_client=outer
        ) as client:
            async with client.stream(
                'POST', 'chat/completions', content=b'{}'
            ) as response:
                with pytest.raises(VerificationError) as caught:
                    async for chunk in response.aiter_bytes():
                        seen.extend(chunk)
    assert bytes(seen) == gateway.response_body
    assert caught.value.failure.code == 'ohttp.decryption_failed'
    assert gateway.streams[0].closed


@pytest.mark.parametrize(
    'method,status', [('HEAD', 200), ('GET', 204), ('GET', 205), ('GET', 304)]
)
async def test_bodyless_responses_still_authenticate_final_chunk(
    method: str, status: int
) -> None:
    gateway = OhttpGateway()
    gateway.response_status = status
    gateway.response_body = b''
    gateway.corrupt_final_response = True
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(gateway.handle)
    ) as outer:
        async with create_ohttp_client(
            gateway.key_config, base_url=BASE_URL, http_client=outer
        ) as client:
            with pytest.raises(VerificationError) as caught:
                await client.request(method, 'chat/completions')
    assert caught.value.failure.code == 'ohttp.decryption_failed'


async def test_streaming_backpressure_early_close_and_cancellation() -> None:
    started, finish = asyncio.Event(), asyncio.Event()

    async def body() -> AsyncIterator[bytes]:
        yield b'data: first\n\n'
        started.set()
        await finish.wait()
        yield b'data: [DONE]\n\n'

    source = Chunks(body())

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={'content-type': 'text/event-stream'}, stream=source
        )

    gateway = OhttpGateway(handler)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(gateway.handle)
    ) as outer:
        async with create_ohttp_client(
            gateway.key_config, base_url=BASE_URL, http_client=outer
        ) as client:
            async with client.stream('POST', 'chat/completions') as response:
                chunks = response.aiter_bytes()
                assert await anext(chunks) == b'data: first\n\n'
                assert not started.is_set()
                pending = asyncio.create_task(anext(chunks))
                await started.wait()
                pending.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await pending
            assert not outer.is_closed
    assert source.closed
    assert gateway.streams[0].closed


@pytest.mark.parametrize(
    'invalid_config',
    [
        b'',
        b'\x01',
        b'\x01\x00\x21' + bytes(38),
        b'\x01\x00\x20' + bytes(32) + b'\x00\x04\x00\x01\x00\x03',
    ],
)
def test_invalid_or_unsupported_key_config_fails_locally(invalid_config: bytes) -> None:
    with pytest.raises(VerificationError) as caught:
        create_ohttp_client(invalid_config, base_url=BASE_URL)
    assert caught.value.failure.code == 'ohttp.key_config_invalid'


async def test_key_config_can_advertise_additional_cipher_suites() -> None:
    gateway = OhttpGateway()
    config = gateway.key_config[:35] + b'\x00\x08\x00\x01\x00\x03\x00\x01\x00\x01'
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(gateway.handle)
    ) as outer:
        async with create_ohttp_client(
            config, base_url=BASE_URL, http_client=outer
        ) as client:
            assert (await client.get('models')).status_code == 200


@pytest.mark.parametrize(
    'base_url',
    [
        'relative/path',
        'ftp://gateway.example/',
        'https://gateway.example:bad/v1',
        'https://[::1/v1',
    ],
)
def test_invalid_base_url_uses_structured_error(base_url: str) -> None:
    with pytest.raises(ApiError) as caught:
        create_ohttp_client(OhttpGateway().key_config, base_url=base_url)
    assert caught.value.failure.code == 'api.invalid_input'
    assert caught.value.failure.details['field'] == 'base_url'


async def test_owned_underlying_transport_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = []
    original_close = httpx.AsyncHTTPTransport.aclose

    async def close(transport: httpx.AsyncHTTPTransport) -> None:
        closed.append(transport)
        await original_close(transport)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, 'aclose', close)
    async with create_ohttp_client(OhttpGateway().key_config, base_url=BASE_URL):
        pass
    assert closed


async def test_outer_network_failure_is_retryable_and_cancellation_is_preserved() -> (
    None
):
    failure: BaseException = httpx.ConnectError('network unavailable')

    async def handle(_request: httpx.Request) -> httpx.Response:
        raise failure

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as outer:
        async with create_ohttp_client(
            OhttpGateway().key_config, base_url=BASE_URL, http_client=outer
        ) as client:
            with pytest.raises(ApiError) as caught:
                await client.get('models')
            assert caught.value.failure.code == 'api.transport_failed'
            assert caught.value.retryable
            assert caught.value.cause is failure
            failure = asyncio.CancelledError('cancelled')
            with pytest.raises(asyncio.CancelledError) as cancelled:
                await client.get('models')
            assert cancelled.value is failure


async def test_cross_origin_and_unusable_key_fail_before_transport() -> None:
    gateway = OhttpGateway()
    config = gateway.key_config[:3] + bytes(32) + gateway.key_config[35:]
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(gateway.handle)
    ) as outer:
        async with create_ohttp_client(
            config, base_url=BASE_URL, http_client=outer
        ) as client:
            with pytest.raises(ApiError) as invalid_url:
                await client.get('https://elsewhere.example/data')
            with pytest.raises(VerificationError) as encryption:
                await client.get('models')
    assert invalid_url.value.failure.code == 'api.invalid_input'
    assert encryption.value.failure.code == 'ohttp.encryption_failed'
    assert gateway.outer_requests == []


@pytest.mark.parametrize(
    'status,retryable', [(302, False), (403, False), (429, True), (503, True)]
)
async def test_outer_http_status_is_structured(status: int, retryable: bool) -> None:
    gateway = OhttpGateway()
    calls = []

    async def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(status, headers={'location': 'https://elsewhere.example'})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handle), follow_redirects=True
    ) as outer:
        async with create_ohttp_client(
            gateway.key_config, base_url=BASE_URL, http_client=outer
        ) as client:
            with pytest.raises(ApiError) as caught:
                await client.get('models')
    assert caught.value.failure.code == 'api.http_status'
    assert caught.value.failure.details == {'resource': 'ohttp', 'status': status}
    assert caught.value.retryable is retryable
    assert len(calls) == 1


async def test_transport_retains_timeouts_and_preserves_tls_verification_failures() -> (
    None
):
    gateway = OhttpGateway()
    failure = verification_failure('binding.spki_fingerprint_mismatch')
    requests = []

    async def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise failure

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as outer:
        async with create_ohttp_client(
            gateway.key_config, base_url=BASE_URL, http_client=outer
        ) as client:
            with pytest.raises(VerificationError) as caught:
                await client.get('models', timeout=httpx.Timeout(1, read=3))
    assert caught.value is failure
    assert requests[0].extensions['timeout']['read'] == 3


@pytest.mark.parametrize(
    'payload',
    [
        b'\x02',  # Request framing in a response.
        b'\x03' + varint(600),
        b'\x03'
        + varint(200)
        + vector(b'Content Type')
        + vector(b'text/plain')
        + b'\0\0\0',
        b'\x03' + varint(200) + b'\0\x05abc',
        b'\x03' + varint(200) + b'\0\x03abc',  # Missing content terminator.
        b'\x03' + varint(200) + b'\0\0\0bad padding',
        b'\x01' + varint(200) + vector(b'\0\0') + b'\0\0',
    ],
)
async def test_authenticated_but_malformed_bhttp_is_rejected(payload: bytes) -> None:
    gateway = OhttpGateway()
    gateway.plaintext_response = payload
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(gateway.handle)
    ) as outer:
        async with create_ohttp_client(
            gateway.key_config, base_url=BASE_URL, http_client=outer
        ) as client:
            with pytest.raises(VerificationError) as caught:
                await client.get('models')
    assert caught.value.failure.code == 'ohttp.decryption_failed'


@pytest.mark.parametrize('framing', [1, 3])
async def test_informational_status_and_omitted_empty_sections(framing: int) -> None:
    gateway = OhttpGateway()
    gateway.plaintext_response = bytes([framing]) + varint(103) + b'\0' + varint(200)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(gateway.handle)
    ) as outer:
        async with create_ohttp_client(
            gateway.key_config, base_url=BASE_URL, http_client=outer
        ) as client:
            response = await client.get('models')
    assert response.status_code == 200
    assert response.content == b''
