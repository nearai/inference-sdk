"""Bounded HTTP 429 retries for live Chat requests, not verification."""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import httpx
from openai import APIConnectionError, RateLimitError

from nearai_inference_sdk import ApiError

logger = logging.getLogger(__name__)


async def retry_rate_limit[T](send: Callable[[], Awaitable[T]]) -> T:
    for backoff_seconds in (5, 10, 20):
        try:
            response = await send()
            if not isinstance(response, httpx.Response) or response.status_code != 429:
                return response
            retry_after = response.headers.get('retry-after', '')
            await response.aclose()
        except (RateLimitError, APIConnectionError, ApiError) as error:
            cause = error.__cause__ if isinstance(error, APIConnectionError) else error
            if isinstance(error, RateLimitError):
                retry_after = error.response.headers.get('retry-after', '')
            elif (
                isinstance(cause, ApiError)
                and cause.failure.code == 'api.http_status'
                and cause.failure.details.get('resource') == 'ohttp'
                and cause.failure.details.get('status') == 429
            ):
                retry_after = cause.failure.details.get('retryAfter', '')
            else:
                raise
        try:
            requested_delay = float(int(retry_after))
        except ValueError:
            try:
                requested_delay = (
                    parsedate_to_datetime(retry_after) - datetime.now(UTC)
                ).total_seconds()
            except (ValueError, TypeError):
                requested_delay = 0
        wait_seconds = max(backoff_seconds, requested_delay)
        logger.warning('Chat returned HTTP 429; retrying in %ss', wait_seconds)
        await asyncio.sleep(wait_seconds)
    return await send()
