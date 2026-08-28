"""Minimal asynchronous HTTP transport used by the default adapters."""

from __future__ import annotations

from asyncio import BaseTransport
import hashlib
from dataclasses import dataclass
from typing import Mapping

import aiohttp
from aiohttp.connector import Connection
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@dataclass(frozen=True, kw_only=True)
class FetchResponse:
    status: int
    body: bytes
    peer_spki_fingerprint: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self) -> str:
        return self.body.decode('utf-8')


async def fetch(
    url: str,
    *,
    method: str = 'GET',
    data: str | bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float | None = None,
    _capture_peer_spki: bool = False,
) -> FetchResponse:
    """Send one request, optionally retaining its TLS peer SPKI fingerprint.

    ``_capture_peer_spki`` is used internally for the Gateway-attestation
    request. aiohttp normally releases a fully buffered response's connection
    before callers can inspect its certificate, so the response class captures
    the peer when the response starts.
    """

    client_timeout = aiohttp.ClientTimeout(total=timeout)
    response_class = (
        _PeerSpkiCapturingResponse if _capture_peer_spki else aiohttp.ClientResponse
    )
    async with aiohttp.ClientSession(
        timeout=client_timeout,
        response_class=response_class,
    ) as session:
        async with session.request(method, url, data=data, headers=headers) as response:
            return FetchResponse(
                status=response.status,
                body=await response.read(),
                peer_spki_fingerprint=(
                    response.peer_spki_fingerprint
                    if isinstance(response, _PeerSpkiCapturingResponse)
                    else None
                ),
            )


class _PeerSpkiCapturingResponse(aiohttp.ClientResponse):
    """Record the peer before aiohttp releases a fully buffered response."""

    peer_spki_fingerprint: str | None = None

    async def start(self, connection: Connection) -> aiohttp.ClientResponse:
        self.peer_spki_fingerprint = _peer_spki_fingerprint(connection.transport)
        return await super().start(connection)


def _peer_spki_fingerprint(transport: BaseTransport | None) -> str | None:
    """Return the SPKI for the TLS transport that made this request."""

    if transport is None:
        return None
    ssl_object = transport.get_extra_info('ssl_object')
    if ssl_object is None:
        return None
    certificate_der = ssl_object.getpeercert(binary_form=True)
    if not isinstance(certificate_der, bytes):
        return None
    certificate = x509.load_der_x509_certificate(certificate_der)
    spki = certificate.public_key().public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()
