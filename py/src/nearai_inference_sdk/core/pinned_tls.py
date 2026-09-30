"""HTTPX-compatible HTTPS transport pinned to supplied SPKI fingerprints."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..utils.common import require_byte_length
from ..utils.errors import verification_failure


def create_pinned_tls_client(
    spki_fingerprint: str | Sequence[str],
) -> httpx.AsyncClient:
    """Create an HTTP client with HTTPS connections pinned to the supplied SPKIs.

    Normal certificate-chain and hostname verification remain enabled. Use the
    returned client as an async context manager, or call ``await client.aclose()``
    when finished. It can also be passed to OpenAI's ``AsyncOpenAI(http_client=)``.
    Pinning checks peer identity; attestation verification establishes trust in it.
    """

    fingerprints = (
        (spki_fingerprint,) if isinstance(spki_fingerprint, str) else spki_fingerprint
    )
    if not fingerprints:
        raise verification_failure('binding.spki_fingerprint_required')
    expected = frozenset(
        require_byte_length(value, 32, 'spki_fingerprint') for value in fingerprints
    )
    return httpx.AsyncClient(transport=_PinnedTlsTransport(expected), timeout=None)


class _PinnedTlsTransport(httpx.AsyncHTTPTransport):
    def __init__(self, expected_spki_fingerprint: frozenset[bytes]) -> None:
        super().__init__()
        self._expected_spki_fingerprint = expected_spki_fingerprint

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme != 'https':
            raise ValueError('Pinned TLS requests require an HTTPS URL')
        previous_trace = request.extensions.get('trace')

        async def trace(event: str, info: dict[str, Any]) -> None:
            if event == 'connection.start_tls.complete':
                stream = info['return_value']
                try:
                    # This awaited httpcore event follows certificate/hostname
                    # validation but precedes all HTTP writes. The pool belongs
                    # to this pin set, so reused connections are already checked.
                    ssl_object = stream.get_extra_info('ssl_object')
                    certificate = x509.load_der_x509_certificate(
                        ssl_object.getpeercert(binary_form=True)
                    )
                    spki = certificate.public_key().public_bytes(
                        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                    )
                    if (
                        hashlib.sha256(spki).digest()
                        not in self._expected_spki_fingerprint
                    ):
                        raise verification_failure('binding.spki_fingerprint_mismatch')
                    if previous_trace is not None:
                        await previous_trace(event, info)
                except BaseException:
                    await stream.aclose()
                    raise
            elif previous_trace is not None:
                await previous_trace(event, info)

        request.extensions['trace'] = trace
        try:
            return await super().handle_async_request(request)
        finally:
            if previous_trace is None:
                request.extensions.pop('trace', None)
            else:
                request.extensions['trace'] = previous_trace
