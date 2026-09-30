"""Bounded HTTP 429 retries for live Chat requests, not verification."""

import asyncio
import logging
from collections.abc import Awaitable, Callable

import httpx
from openai import RateLimitError

logger = logging.getLogger(__name__)


async def retry_rate_limit[T](send: Callable[[], Awaitable[T]]) -> T:
    for backoff_seconds in (5, 10, 20):
        try:
            response = await send()
            if not isinstance(response, httpx.Response) or response.status_code != 429:
                return response
            retry_after = response.headers.get('retry-after', '')
            await response.aclose()
        except RateLimitError as error:
            retry_after = error.response.headers.get('retry-after', '')
        try:
            requested_delay = int(retry_after)
        except ValueError:
            requested_delay = 0
        wait_seconds = max(backoff_seconds, requested_delay)
        logger.warning('Chat returned HTTP 429; retrying in %ss', wait_seconds)
        await asyncio.sleep(wait_seconds)
    return await send()
