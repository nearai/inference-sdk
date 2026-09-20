"""Independent in-process chunked OHTTP gateway for SDK integration tests."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable, Callable
from io import BytesIO

import httpx
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from pyhpke import AEADId, CipherSuite, ContextInterface, KDFId, KEMId


def varint(value: int) -> bytes:
    if value < 64:
        return bytes([value])
    if value < 16384:
        return (value | 0x4000).to_bytes(2, 'big')
    if value < 1 << 30:
        return (value | 0x80000000).to_bytes(4, 'big')
    return (value | 0xC000000000000000).to_bytes(8, 'big')


def vector(value: bytes) -> bytes:
    return varint(len(value)) + value


def read_varint(data: BytesIO) -> int:
    first = data.read(1)
    if not first:
        raise ValueError('Unexpected end of test message')
    size = 1 << (first[0] >> 6)
    rest = data.read(size - 1)
    assert len(rest) == size - 1
    return int.from_bytes(bytes([first[0] & 0x3F]) + rest, 'big')


def read_vector(data: BytesIO) -> bytes:
    length = read_varint(data)
    result = data.read(length)
    assert len(result) == length
    return result


def read_fields(data: BytesIO, known: bool) -> list[tuple[bytes, bytes]]:
    fields = []
    if known:
        data = BytesIO(read_vector(data))
        while data.tell() < len(data.getbuffer()):
            fields.append((read_vector(data), read_vector(data)))
    else:
        while name := read_vector(data):
            fields.append((name, read_vector(data)))
    return fields


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks: AsyncIterator[bytes]) -> None:
        self.chunks = chunks
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self.chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True
        await self.chunks.aclose()


class OhttpGateway:
    def __init__(
        self,
        handler: Callable[[httpx.Request], Awaitable[httpx.Response]] | None = None,
    ) -> None:
        self.suite = CipherSuite.new(
            KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM
        )
        self.keys = self.suite.kem.derive_key_pair(b'OHTTP SDK test gateway')
        self.key_config = (
            b'\x01\x00\x20'
            + self.keys.public_key.to_public_bytes()
            + b'\x00\x04\x00\x01\x00\x01'
        )
        self.handler = handler
        self.requests: list[httpx.Request] = []
        self.outer_requests: list[httpx.Request] = []
        self.streams: list[Chunks] = []
        self.response_status = 200
        self.response_headers = {'content-type': 'application/json'}
        self.response_body = b'{ "id": "test-completion", "choices": [] }'
        self.truncate_final_response = False
        self.corrupt_final_response = False
        self.omit_final_response = False
        self.fragment_size = 0
        self.response_framing = 3
        self.plaintext_response: bytes | None = None

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.outer_requests.append(request)
        assert request.method == 'POST' and request.url.path == '/ohttp'
        assert request.headers['content-type'] == 'message/ohttp-chunked-req'
        data = BytesIO(await request.aread())
        header, enc = data.read(7), data.read(32)
        assert header == b'\x01\x00\x20\x00\x01\x00\x01'
        context = self.suite.create_recipient_context(
            enc, self.keys.private_key, b'message/bhttp chunked request\0' + header
        )
        plaintext = []
        while size := read_varint(data):
            plaintext.append(context.open(data.read(size)))
        plaintext.append(context.open(data.read(), b'final'))
        bhttp = BytesIO(b''.join(plaintext))
        framing = read_varint(bhttp)
        assert framing in (0, 2)
        method, scheme, authority, path = (read_vector(bhttp) for _ in range(4))
        headers = read_fields(bhttp, framing == 0)
        body = read_vector(bhttp)
        if framing == 2:
            while chunk := read_vector(bhttp):
                body += chunk
        assert read_fields(bhttp, framing == 0) == []
        assert not any(bhttp.read())
        inner = httpx.Request(
            method.decode(),
            b''.join((scheme, b'://', authority, path)).decode(),
            headers=headers,
            content=body,
        )
        self.requests.append(inner)
        response = (
            await self.handler(inner)
            if self.handler
            else httpx.Response(
                self.response_status,
                headers=self.response_headers,
                content=self.response_body,
            )
        )
        stream = Chunks(self._response_chunks(response, context, enc))
        self.streams.append(stream)
        return httpx.Response(
            200,
            headers={'content-type': 'message/ohttp-chunked-res'},
            stream=stream,
        )

    async def _response_chunks(
        self,
        response: httpx.Response,
        context: ContextInterface,
        enc: bytes,
    ) -> AsyncIterator[bytes]:
        response_nonce = os.urandom(16)
        extract = hmac.HMAC(enc + response_nonce, hashes.SHA256())
        extract.update(context.export(b'message/bhttp chunked response', 16))
        prk = extract.finalize()
        key = HKDFExpand(hashes.SHA256(), 16, b'key').derive(prk)
        nonce = HKDFExpand(hashes.SHA256(), 12, b'nonce').derive(prk)
        cipher = AESGCM(key)
        counter = 0

        def seal(plaintext: bytes, final: bool = False) -> bytes:
            nonlocal counter
            iv = (int.from_bytes(nonce, 'big') ^ counter).to_bytes(12, 'big')
            counter += 1
            ciphertext = cipher.encrypt(iv, plaintext, b'final' if final else b'')
            return varint(0 if final else len(ciphertext)) + ciphertext

        async def plaintext_chunks() -> AsyncIterator[bytes]:
            if self.plaintext_response is not None:
                yield self.plaintext_response
                return
            fields = b''.join(
                vector(k.lower()) + vector(v) for k, v in response.headers.raw
            )
            if self.response_framing == 1:
                yield (
                    b'\x01'
                    + varint(response.status_code)
                    + vector(fields)
                    + vector(await response.aread())
                )
            else:
                yield b'\x03' + varint(response.status_code) + fields + b'\0'
                async for chunk in response.aiter_bytes():
                    if chunk:
                        yield vector(chunk)
                yield b'\0'
            yield b'\0'

        async def frames() -> AsyncIterator[bytes]:
            try:
                yield response_nonce
                async for chunk in plaintext_chunks():
                    for start in range(0, len(chunk), 16384):
                        yield seal(chunk[start : start + 16384])
                if not self.omit_final_response:
                    final = seal(b'', True)
                    if self.truncate_final_response:
                        final = final[:-1]
                    if self.corrupt_final_response:
                        final = final[:-1] + bytes([final[-1] ^ 1])
                    yield final
            finally:
                await response.aclose()

        async for frame in frames():
            if self.fragment_size:
                for start in range(0, len(frame), self.fragment_size):
                    yield frame[start : start + self.fragment_size]
            else:
                yield frame
