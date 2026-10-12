"""Shared configuration and receipt-propagation handling for live tests."""

import asyncio
import os
from collections.abc import Awaitable, Callable

from nearai_inference_sdk import ApiError


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f'{name} is required for live E2E tests')
    return value


async def retry_receipt[T](lookup: Callable[[], Awaitable[T]]) -> T:
    # Retry receipt propagation only, never inference or cryptographic failures.
    for delay in (0.5, 1, 2, 4):
        try:
            return await lookup()
        except ApiError as error:
            if not error.retryable:
                raise
        await asyncio.sleep(delay)
    return await lookup()
