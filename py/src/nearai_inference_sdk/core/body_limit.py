"""Bound retained inference bodies independently of declared Content-Length."""

from collections.abc import AsyncIterator, Iterator

from ..utils.errors import api_failure


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
