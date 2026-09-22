"""HTTPX transport for RFC 9292 BHTTP and draft-08 chunked OHTTP.

HPKE and its KDF/AEAD operations are provided by PyHPKE. This module only
implements message framing. A successfully consumed response authenticates
every encrypted chunk, including the final chunk after any SSE ``[DONE]``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass

import httpx
from pyhpke import AEADId, CipherSuite, ContextInterface, KDFId, KEMId, KEMKeyInterface

from ..utils.errors import (
    ApiError,
    VerificationError,
    api_failure,
    verification_failure,
)

_REQUEST_LABEL = b'message/bhttp chunked request'
_RESPONSE_LABEL = b'message/bhttp chunked response'
_CHUNK_SIZE = 16_384
_TAG_SIZE = 16
_MAX_MESSAGE_SIZE = 1 << 30
_MAX_FIELD_SECTION_SIZE = 1 << 20
_SUITE_IDS = b'\x00\x20\x00\x01\x00\x01'
_SUITE = CipherSuite.new(
    KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM
)
_HOP_BY_HOP = {
    b'connection',
    b'proxy-connection',
    b'keep-alive',
    b'transfer-encoding',
    b'upgrade',
    b'te',
    b'trailer',
}
_INNER_HEADERS = {
    'host',
    'transfer-encoding',
    'x-signing-algo',
    'x-client-pub-key',
    'x-model-pub-key',
    'x-encryption-version',
    'x-encrypt-all-fields',
}


def create_ohttp_client(
    key_config: bytes,
    *,
    base_url: str,
    http_client: httpx.AsyncClient | None = None,
    forwarded_headers: Sequence[str] = (),
) -> httpx.AsyncClient:
    """Create an encrypted client from a caller-authenticated key configuration.

    Requests to the configured origin are sent to its ``/ohttp`` endpoint.
    Authorization and explicitly forwarded headers are visible to that endpoint;
    content and field-encryption headers stay inside the encrypted request.
    Request bodies are buffered, responses stream without changing body bytes.

    Close the returned client when finished. A supplied ``http_client`` remains
    owned by its caller, including when it is a client with pinned TLS.
    """
    try:
        config = _KeyConfig.parse(key_config)
    except Exception as cause:
        raise verification_failure('ohttp.key_config_invalid', cause=cause) from cause
    try:
        url = httpx.URL(base_url)
        if url.scheme not in ('https', 'http') or not url.host:
            raise ValueError('Expected an absolute HTTP(S) URL')
    except (httpx.InvalidURL, ValueError) as cause:
        raise api_failure(
            'api.invalid_input',
            {
                'field': 'base_url',
                'reason': 'invalid_url',
                'expected': 'an absolute HTTP(S) URL',
            },
            cause=cause,
        ) from cause
    transport = _OhttpTransport(config, url, http_client, forwarded_headers)
    return httpx.AsyncClient(transport=transport, base_url=base_url, timeout=None)


@dataclass(frozen=True)
class _KeyConfig:
    header: bytes
    public_key: KEMKeyInterface

    @classmethod
    def parse(cls, data: bytes) -> _KeyConfig:
        if len(data) < 41 or data[1:3] != b'\x00\x20':
            raise ValueError('Expected an X25519 OHTTP key configuration')
        size = int.from_bytes(data[35:37], 'big')
        if size == 0 or size % 4 or len(data) != 37 + size:
            raise ValueError('Invalid OHTTP symmetric algorithm list')
        if b'\x00\x01\x00\x01' not in (
            data[offset : offset + 4] for offset in range(37, len(data), 4)
        ):
            raise ValueError(
                'OHTTP configuration does not support HKDF-SHA256/AES128-GCM'
            )
        return cls(data[:1] + _SUITE_IDS, _SUITE.kem.deserialize_public_key(data[3:35]))


class _OhttpTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        config: _KeyConfig,
        base_url: httpx.URL,
        client: httpx.AsyncClient | None,
        forwarded_headers: Sequence[str],
    ) -> None:
        self._config = config
        self._relay = base_url.copy_with(path='/ohttp', query=None, fragment=None)
        self._client = client if client is not None else httpx.AsyncClient(timeout=None)
        self._owns_client = client is None
        self._forwarded_headers = {
            'authorization',
            *(name.lower() for name in forwarded_headers),
        }

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if (request.url.scheme, request.url.host, request.url.port) != (
            self._relay.scheme,
            self._relay.host,
            self._relay.port,
        ):
            raise api_failure(
                'api.invalid_input',
                {
                    'field': 'request.url',
                    'reason': 'invalid_url',
                    'expected': 'the configured OHTTP origin',
                },
            )
        try:
            plaintext = _encode_request(request, await request.aread())
            enc, context = _SUITE.create_sender_context(
                self._config.public_key, _REQUEST_LABEL + b'\0' + self._config.header
            )
            frames = [self._config.header, enc]
            for offset in range(0, len(plaintext), _CHUNK_SIZE):
                final = offset + _CHUNK_SIZE >= len(plaintext)
                ciphertext = context.seal(
                    plaintext[offset : offset + _CHUNK_SIZE], b'final' if final else b''
                )
                frames.extend((_varint(0 if final else len(ciphertext)), ciphertext))
            body = b''.join(frames)
        except Exception as cause:
            raise verification_failure(
                'ohttp.encryption_failed', cause=cause
            ) from cause

        headers = [
            (name, value)
            for name, value in request.headers.raw
            if name.decode('ascii').lower() in self._forwarded_headers
            and not name.decode('ascii').lower().startswith('content-')
            and name.decode('ascii').lower() not in _INNER_HEADERS
        ]
        headers.append((b'content-type', b'message/ohttp-chunked-req'))
        outer_request = httpx.Request(
            'POST',
            self._relay,
            headers=headers,
            content=body,
            extensions=dict(request.extensions),
        )
        # RFC 10036 advises incremental forwarding of this request message only.
        outer_request.headers['incremental'] = '?1'
        try:
            outer = await self._client.send(
                outer_request, stream=True, auth=None, follow_redirects=False
            )
        except (ApiError, VerificationError):
            raise
        except Exception as cause:
            raise api_failure(
                'api.transport_failed',
                {'resource': 'ohttp', 'reason': 'request'},
                retryable=True,
                cause=cause,
            ) from cause
        if not outer.is_success:
            await outer.aclose()
            raise api_failure(
                'api.http_status',
                {'resource': 'ohttp', 'status': outer.status_code},
                retryable=outer.status_code == 429 or outer.status_code >= 500,
            )

        try:
            if (
                outer.headers.get('content-type', '').split(';', 1)[0].strip().lower()
                != 'message/ohttp-chunked-res'
            ):
                raise ValueError('Expected a chunked OHTTP response')
            reader = _Reader(_decrypt_response(outer, context, enc))
            framing = await reader.varint()
            if framing not in (1, 3):
                raise ValueError('Expected a BHTTP response')
            known_length = framing == 1
            while True:
                status = await reader.varint()
                if not 100 <= status <= 599:
                    raise ValueError('Invalid BHTTP status')
                response_headers = await _read_fields(reader, known_length)
                if status >= 200:
                    break
            stream = _ResponseBody(reader, known_length, outer)
            if request.method == 'HEAD' or status in (204, 205, 304):
                async for _ in stream:
                    pass
                return httpx.Response(status, headers=response_headers, content=b'')
            return httpx.Response(status, headers=response_headers, stream=stream)
        except BaseException as cause:
            await outer.aclose()
            if not isinstance(cause, Exception):
                raise
            raise verification_failure(
                'ohttp.decryption_failed', cause=cause
            ) from cause

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def _varint(value: int) -> bytes:
    for size, bits in ((1, 6), (2, 14), (4, 30), (8, 62)):
        if value < 1 << bits:
            return (value | ((size.bit_length() - 1) << bits)).to_bytes(size, 'big')
    raise ValueError('BHTTP integer too large')


def _vector(value: bytes) -> bytes:
    return _varint(len(value)) + value


def _encode_request(request: httpx.Request, body: bytes) -> bytes:
    excluded = _HOP_BY_HOP | {
        name.strip().lower().encode('ascii')
        for name in request.headers.get('connection', '').split(',')
    }
    fields = b''.join(
        _vector(name.lower()) + _vector(value)
        for name, value in request.headers.raw
        if name.lower() not in excluded
    )
    # RFC 9292 keeps Host in the field section, with an empty authority.
    authority = b'' if 'host' in request.headers else request.url.netloc
    encoded = (
        b'\0'
        + b''.join(
            _vector(value)
            for value in (
                request.method.encode('ascii'),
                request.url.raw_scheme,
                authority,
                request.url.raw_path,
            )
        )
        + _vector(fields)
        + _vector(body)
        + b'\0'
    )
    encoded += b'\0' * (-len(encoded) % _CHUNK_SIZE)
    if len(encoded) > _MAX_MESSAGE_SIZE:
        raise ValueError('OHTTP request exceeds the message limit')
    return encoded


class _Reader:
    """An incremental reader that never concatenates an unconsumed body."""

    def __init__(self, chunks: AsyncIterator[bytes]) -> None:
        self._chunks = chunks
        self._pending = memoryview(b'')
        self.position = 0

    async def some(self, size: int) -> bytes:
        while not self._pending:
            try:
                self._pending = memoryview(await anext(self._chunks))
            except StopAsyncIteration:
                return b''
        result = bytes(self._pending[:size])
        self._pending = self._pending[len(result) :]
        self.position += len(result)
        return result

    async def exact(self, size: int) -> bytes:
        pieces: list[bytes] = []
        while size:
            piece = await self.some(size)
            if not piece:
                raise ValueError('Truncated OHTTP/BHTTP message')
            pieces.append(piece)
            size -= len(piece)
        return b''.join(pieces)

    async def varint(self, *, eof_zero: bool = False) -> int:
        first = await self.some(1)
        if not first:
            if eof_zero:
                return 0
            raise ValueError('Missing OHTTP/BHTTP integer')
        size = 1 << (first[0] >> 6)
        return int.from_bytes(
            bytes([first[0] & 63]) + await self.exact(size - 1), 'big'
        )


async def _one_chunk(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _read_fields(
    reader: _Reader, known_length: bool
) -> list[tuple[bytes, bytes]]:
    if known_length:
        section_size = await reader.varint(eof_zero=True)
        if section_size > _MAX_FIELD_SECTION_SIZE:
            raise ValueError('BHTTP field section exceeds the limit')
        reader = _Reader(_one_chunk(await reader.exact(section_size)))
    fields: list[tuple[bytes, bytes]] = []
    total = 0
    while True:
        if known_length and reader.position == section_size:
            return fields
        size = await reader.varint(eof_zero=not known_length and not fields)
        if not size:
            if known_length:
                raise ValueError('Empty BHTTP field name')
            return fields
        total += size
        if total > _MAX_FIELD_SECTION_SIZE:
            raise ValueError('BHTTP field section exceeds the limit')
        name = await reader.exact(size)
        size = await reader.varint()
        total += size
        if total > _MAX_FIELD_SECTION_SIZE:
            raise ValueError('BHTTP field section exceeds the limit')
        value = await reader.exact(size)
        if any(
            c not in b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz"
            for c in name.lower()
        ) or any(c in value for c in (b'\0', b'\r', b'\n')):
            raise ValueError('Invalid BHTTP header')
        fields.append((name, value))


async def _decrypt_response(
    response: httpx.Response,
    context: ContextInterface,
    enc: bytes,
) -> AsyncIterator[bytes]:
    encrypted = _Reader(response.aiter_bytes())
    response_nonce = await encrypted.exact(16)
    secret = context.export(_RESPONSE_LABEL, 16)
    prk = _SUITE.kdf.extract(enc + response_nonce, secret)
    key = _SUITE.aead.import_key(_SUITE.kdf.expand(prk, b'key', 16))
    nonce = _SUITE.kdf.expand(prk, b'nonce', 12)
    counter = 0
    total = 0
    while True:
        size = await encrypted.varint()
        if counter >= 1 << 32 or size > _CHUNK_SIZE + _TAG_SIZE:
            raise ValueError('OHTTP chunk exceeds the limit')
        final = size == 0
        if final:
            pieces = []
            remaining = _CHUNK_SIZE + _TAG_SIZE
            while piece := await encrypted.some(remaining + 1):
                remaining -= len(piece)
                if remaining < 0:
                    raise ValueError('OHTTP final chunk exceeds the limit')
                pieces.append(piece)
            ciphertext = b''.join(pieces)
        else:
            ciphertext = await encrypted.exact(size)
        if len(ciphertext) < _TAG_SIZE or (not final and len(ciphertext) == _TAG_SIZE):
            raise ValueError('Invalid OHTTP chunk length')
        chunk_nonce = (int.from_bytes(nonce, 'big') ^ counter).to_bytes(12, 'big')
        plaintext = key.open(ciphertext, chunk_nonce, b'final' if final else b'')
        counter += 1
        total += len(plaintext)
        if total > _MAX_MESSAGE_SIZE:
            raise ValueError('OHTTP response exceeds the message limit')
        if plaintext:
            yield plaintext
        if final:
            return


class _ResponseBody(httpx.AsyncByteStream):
    def __init__(
        self, reader: _Reader, known_length: bool, outer: httpx.Response
    ) -> None:
        self._reader = reader
        self._known_length = known_length
        self._outer = outer

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            first = True
            while size := await self._reader.varint(eof_zero=first):
                first = False
                if size > _MAX_MESSAGE_SIZE:
                    raise ValueError('BHTTP content exceeds the message limit')
                while size:
                    piece = await self._reader.some(min(size, _CHUNK_SIZE))
                    if not piece:
                        raise ValueError('Truncated BHTTP content')
                    size -= len(piece)
                    yield piece
                if self._known_length:
                    break
            await _read_fields(self._reader, self._known_length)
            # Consume padding and authenticate final OHTTP framing even when
            # content has ended (including SSE [DONE] or an empty entity).
            while padding := await self._reader.some(_CHUNK_SIZE):
                if any(padding):
                    raise ValueError('Invalid BHTTP padding')
        except Exception as cause:
            raise verification_failure(
                'ohttp.decryption_failed', cause=cause
            ) from cause
        finally:
            await self._outer.aclose()

    async def aclose(self) -> None:
        await self._outer.aclose()
