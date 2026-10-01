from unittest.mock import AsyncMock

import httpx
import pytest
from openai import APIConnectionError

from e2e.retry import retry_rate_limit
from nearai_inference_sdk.utils.errors import api_failure


@pytest.mark.parametrize('wrapped', [False, True])
async def test_retries_ohttp_rate_limits_after_retry_after(monkeypatch, wrapped):
    cause = api_failure(
        'api.http_status',
        {'resource': 'ohttp', 'status': 429, 'retryAfter': '12'},
        retryable=True,
    )
    error = cause
    if wrapped:
        error = APIConnectionError(
            request=httpx.Request('POST', 'https://test.invalid')
        )
        error.__cause__ = cause
    send = AsyncMock(side_effect=[error, 'ok'])
    sleep = AsyncMock()
    monkeypatch.setattr('e2e.retry.asyncio.sleep', sleep)

    result = await retry_rate_limit(send)

    assert result == 'ok'
    assert send.await_count == 2
    sleep.assert_awaited_once_with(12)


async def test_does_not_retry_an_ohttp_server_error():
    error = api_failure(
        'api.http_status', {'resource': 'ohttp', 'status': 503}, retryable=True
    )
    send = AsyncMock(side_effect=error)
    with pytest.raises(type(error)) as raised:
        await retry_rate_limit(send)
    assert raised.value is error
    assert send.await_count == 1
