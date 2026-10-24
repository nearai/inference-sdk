"""Body limits also bound the memory overhead of fragmented input."""

import tracemalloc

import pytest

from nearai_inference_sdk import ApiError
from nearai_inference_sdk.core.body_limit import read_bounded_body


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
