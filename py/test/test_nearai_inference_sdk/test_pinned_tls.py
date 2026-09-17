from __future__ import annotations

import asyncio
import hashlib
import ssl
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from nearai_inference_sdk import VerificationError
from nearai_inference_sdk.core.pinned_tls import create_pinned_tls_client


@dataclass
class TlsServer:
    url: str
    spki_fingerprint: str
    trusted_context: ssl.SSLContext
    received_headers: list[str | None] = field(default_factory=list)
    requests: list[tuple[str | None, bytes]] = field(default_factory=list)
    finish_stream: asyncio.Event = field(default_factory=asyncio.Event)


@pytest_asyncio.fixture
async def tls_server(tmp_path: Path) -> AsyncIterator[TlsServer]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
        .sign(key, hashes.SHA256())
    )
    certificate_path = tmp_path / 'certificate.pem'
    key_path = tmp_path / 'key.pem'
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate_path, key_path)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    server = TlsServer(
        url='',
        spki_fingerprint=hashlib.sha256(spki).hexdigest(),
        trusted_context=ssl.create_default_context(cafile=str(certificate_path)),
    )

    async def receive(request: web.Request) -> web.StreamResponse:
        server.received_headers.append(request.headers.get('Authorization'))
        server.requests.append(
            (request.headers.get('Authorization'), await request.read())
        )
        if request.path != '/stream':
            return web.Response(body=b'complete')
        response = web.StreamResponse()
        await response.prepare(request)
        await response.write(b'first')
        await server.finish_stream.wait()
        await response.write(b'second')
        return response

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', receive)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0, ssl_context=server_context)
    await site.start()
    server.url = f'https://localhost:{runner.addresses[0][1]}'
    try:
        yield server
    finally:
        server.finish_stream.set()
        await runner.cleanup()


def trust_test_certificate(monkeypatch: pytest.MonkeyPatch, server: TlsServer) -> None:
    initialize_transport = httpx.AsyncHTTPTransport.__init__

    def trusted_transport(transport: httpx.AsyncHTTPTransport) -> None:
        initialize_transport(transport, verify=server.trusted_context)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, '__init__', trusted_transport)


async def test_pinned_client_streams_and_reuses_verified_tls_connections(
    monkeypatch: pytest.MonkeyPatch, tls_server: TlsServer
) -> None:
    trust_test_certificate(monkeypatch, tls_server)
    events: list[str] = []

    async def trace(event: str, _info: dict[str, object]) -> None:
        events.append(event)

    async with create_pinned_tls_client(tls_server.spki_fingerprint) as client:
        async with client.stream(
            'POST',
            f'{tls_server.url}/stream',
            headers={'Authorization': 'Bearer test'},
            content=b'prompt',
            extensions={'trace': trace},
        ) as response:
            chunks = response.aiter_bytes()
            assert await anext(chunks) == b'first'
            tls_server.finish_stream.set()
            assert b''.join([chunk async for chunk in chunks]) == b'second'
        response = await client.get(
            f'{tls_server.url}/again', extensions={'trace': trace}
        )

    assert response.content == b'complete'
    assert tls_server.requests == [('Bearer test', b'prompt'), (None, b'')]
    assert events.count('connection.start_tls.complete') == 1
    assert events.index('connection.start_tls.complete') < events.index(
        'http11.send_request_headers.started'
    )


async def test_pinned_client_honors_an_explicit_httpx_read_timeout(
    monkeypatch: pytest.MonkeyPatch, tls_server: TlsServer
) -> None:
    trust_test_certificate(monkeypatch, tls_server)

    async with create_pinned_tls_client(tls_server.spki_fingerprint) as client:
        async with client.stream(
            'GET',
            f'{tls_server.url}/stream',
            timeout=httpx.Timeout(None, read=0.01),
        ) as response:
            chunks = response.aiter_bytes()
            assert await anext(chunks) == b'first'
            with pytest.raises(httpx.ReadTimeout):
                await anext(chunks)


async def test_spki_mismatch_stops_request_before_headers_and_body_are_sent(
    monkeypatch: pytest.MonkeyPatch, tls_server: TlsServer
) -> None:
    trust_test_certificate(monkeypatch, tls_server)

    async with create_pinned_tls_client('00' * 32) as client:
        with pytest.raises(VerificationError) as raised:
            await client.post(
                tls_server.url,
                headers={'Authorization': 'Bearer secret'},
                content=b'private prompt',
            )

    assert raised.value.failure.code == 'binding.spki_fingerprint_mismatch'
    assert tls_server.received_headers == []
    assert tls_server.requests == []


@pytest.mark.parametrize('invalid_certificate', ['untrusted', 'wrong_hostname'])
async def test_spki_match_does_not_replace_certificate_or_hostname_verification(
    monkeypatch: pytest.MonkeyPatch,
    tls_server: TlsServer,
    invalid_certificate: str,
) -> None:
    url = tls_server.url
    if invalid_certificate == 'wrong_hostname':
        trust_test_certificate(monkeypatch, tls_server)
        url = url.replace('localhost', '127.0.0.1')

    async with create_pinned_tls_client(tls_server.spki_fingerprint) as client:
        with pytest.raises(httpx.TransportError):
            await client.post(url, content=b'private prompt')

    assert tls_server.received_headers == []
    assert tls_server.requests == []
