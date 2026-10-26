"""Bound retained inference bodies independently of declared Content-Length."""

from collections.abc import AsyncIterator, Iterator
from types import AsyncGeneratorType, GeneratorType

import httpx
from httpx._content import AsyncIteratorByteStream, IteratorByteStream

from ..utils.errors import api_failure


class BufferedResponse(httpx.Response):
    """Coalesce buffered reads without delaying streamed events."""

    async def aread(self) -> bytes:
        if not hasattr(self, '_content'):
            body = bytearray()
            async for chunk in self.aiter_bytes():
                body.extend(chunk)
            self._content = bytes(body)
        return self._content


def require_body_size(size: int, limit: int) -> None:
    if size > limit:
        raise api_failure('api.body_too_large')


async def read_bounded_body(stream: AsyncIterator[bytes], limit: int) -> bytes:
    body = bytearray()
    async for chunk in stream:
        require_body_size(len(body) + len(chunk), limit)
        body.extend(chunk)
    return bytes(body)


def read_bounded_sync_body(stream: Iterator[bytes], limit: int) -> bytes:
    body = bytearray()
    for chunk in stream:
        require_body_size(len(body) + len(chunk), limit)
        body.extend(chunk)
    return bytes(body)


async def read_bounded_request_body(request: httpx.Request, limit: int) -> bytes:
    stream = request.stream
    try:
        if isinstance(stream, httpx.AsyncByteStream):
            return await read_bounded_body(aiter(stream), limit)
        return read_bounded_sync_body(iter(stream), limit)
    finally:
        # HTTPX 0.28 wraps iterable content without forwarding close/aclose.
        # Close generators and HTTPX streams; caller-owned files stay open.
        if type(stream) in (IteratorByteStream, AsyncIteratorByteStream):
            source = stream._stream
            if isinstance(source, (AsyncGeneratorType, httpx.AsyncByteStream)):
                await source.aclose()
            elif isinstance(source, (GeneratorType, httpx.SyncByteStream)):
                source.close()
        if isinstance(stream, httpx.AsyncByteStream):
            await stream.aclose()
        else:
            stream.close()
