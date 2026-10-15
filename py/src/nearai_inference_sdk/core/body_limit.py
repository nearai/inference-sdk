"""Bound retained inference bodies independently of declared Content-Length."""

from collections.abc import AsyncIterator

from ..utils.errors import api_failure


def require_body_size(size: int, limit: int) -> None:
    if size > limit:
        raise api_failure('api.body_too_large')


async def read_bounded_body(stream: AsyncIterator[bytes], limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in stream:
        require_body_size(size + len(chunk), limit)
        size += len(chunk)
        chunks.append(chunk)
    return b''.join(chunks)
