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
) -> FetchResponse:
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=client_timeout) as session:
        async with session.request(method, url, data=data, headers=headers) as response:
            return FetchResponse(status=response.status, body=await response.read())


async def fetch_gateway_attestation(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> FetchResponse:
    """Fetch Gateway evidence and capture the TLS peer for this request."""

    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(
        timeout=client_timeout,
        response_class=_GatewayAttestationResponse,
    ) as session:
        async with session.get(url, headers=headers) as response:
            return FetchResponse(
                status=response.status,
                body=await response.read(),
                peer_spki_fingerprint=response.peer_spki_fingerprint,
            )


class _GatewayAttestationResponse(aiohttp.ClientResponse):
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
