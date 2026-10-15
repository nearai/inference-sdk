"""Body limits also bound the memory overhead of fragmented input."""

import asyncio
import tracemalloc
from types import SimpleNamespace

import httpx
import pytest

from nearai_inference_sdk import ApiError
from nearai_inference_sdk.core.body_limit import read_bounded_body
from nearai_inference_sdk.core.inference_client import _CapturedResponseStream


async def test_fragmented_body_has_bounded_memory_overhead():
    size = 200_000

    async def fragments():
        for index in range(size // 2):
            yield (index % 65536).to_bytes(2, 'little')

    tracemalloc.start()
    try:
        body = await read_bounded_body(fragments(), size)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(body) == size
    assert body[:4] == b'\x00\x00\x01\x00'
    # Permit buffer growth and the final immutable copy, but not one object and
    # join descriptor per fragment (over 60x the input size in the regression).
    assert peak < size * 8


async def test_fragmented_chat_capture_has_bounded_memory_overhead():
    class Fragments(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'{"id":"fragmented","value":"'
            for index in range(100_000):
                yield f'{index % 100:02d}'.encode()
            yield b'"}'

    response = httpx.Response(
        200,
        stream=Fragments(),
        request=httpx.Request('POST', 'https://example.test', content=b'{}'),
    )
    retained = asyncio.get_running_loop().create_future()
    registered = []
    stream = _CapturedResponseStream(
        response,
        retained,
        registered.append,
        SimpleNamespace(_response_byte_limit=lambda _: 210_000, _responses={}),
    )
    tracemalloc.start()
    try:
        async for _ in stream:
            pass
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        await stream.aclose()
    body = await retained
    assert registered == ['fragmented']
    assert 200_000 < len(body) < 210_000
    assert peak < len(body) * 8


async def test_oversized_body_stops_consuming_at_first_excess_chunk():
    consumed = 0

    async def fragments():
        nonlocal consumed
        for _ in range(100):
            consumed += 1
            yield b'ab'

    with pytest.raises(ApiError, match='api.body_too_large'):
        await read_bounded_body(fragments(), 5)
    assert consumed == 3
