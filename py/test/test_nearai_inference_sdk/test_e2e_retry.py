import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest
from openai import APIConnectionError, RateLimitError

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
    monkeypatch.setattr('e2e.retry.sleep', sleep)

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


async def test_builtin_chat_has_one_shared_four_post_retry_budget(monkeypatch):
    from openai import RateLimitError

    from .test_inference_client import MESSAGES, MODEL, Gateway

    gateway = Gateway()
    handle = gateway.handle
    posts = 0

    async def respond(request):
        nonlocal posts
        if request.url.path == '/v1/chat/completions':
            posts += 1
            return httpx.Response(429, headers={'Retry-After': '12'})
        return await handle(request)

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    sleep = AsyncMock()
    monkeypatch.setattr('e2e.retry.sleep', sleep)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(RateLimitError):
            await retry_rate_limit(
                lambda: client.chat.completions.create(model=MODEL, messages=MESSAGES)
            )
    assert posts == 4
    assert [call.args[0] for call in sleep.await_args_list] == [12, 12, 20]


@pytest.mark.parametrize('statuses', [(429, 200), (503,), (200,)])
async def test_success_and_other_errors_are_not_replayed(monkeypatch, statuses):
    responses = [httpx.Response(status) for status in statuses]
    send = AsyncMock(side_effect=responses)
    monkeypatch.setattr('e2e.retry.sleep', AsyncMock())
    response = await retry_rate_limit(send)
    assert response is responses[-1]
    assert send.await_count == len(statuses)


async def test_oversized_retry_after_waits_until_the_case_deadline():
    response = httpx.Response(429, headers={'Retry-After': '9' * 5000})
    send = AsyncMock(return_value=response)
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.01):
            await retry_rate_limit(send)
    assert send.await_count == 1
    assert response.is_closed


@pytest.mark.parametrize(
    ('retry_after', 'long_wait'),
    [('9' * 400, True), ('9' * 5000, True), ('inf', False), ('invalid', False)],
    ids=['float-overflow', 'integer-limit', 'infinity', 'invalid'],
)
@pytest.mark.parametrize('interface', ['httpx', 'openai', 'ohttp'])
async def test_retry_after_overflow_and_invalid_values(
    monkeypatch, retry_after, long_wait, interface
):
    responses = [
        httpx.Response(
            429,
            headers={'Retry-After': retry_after},
            request=httpx.Request('POST', 'https://test.invalid'),
        )
        for _ in range(3)
    ]
    if interface == 'openai':
        failures = [
            RateLimitError('limited', response=response, body=None)
            for response in responses
        ]
    elif interface == 'ohttp':
        failures = [
            api_failure(
                'api.http_status',
                {'resource': 'ohttp', 'status': 429, 'retryAfter': retry_after},
                retryable=True,
            )
            for _ in responses
        ]
    else:
        failures = responses
    send = AsyncMock(side_effect=[*failures, 'ok'])
    sleep = AsyncMock()
    monkeypatch.setattr('e2e.retry.sleep', sleep)

    if long_wait:
        sleep.side_effect = asyncio.CancelledError
        with pytest.raises(asyncio.CancelledError):
            await retry_rate_limit(send)
        assert send.await_count == 1
        assert sleep.await_args.args[0] > 180
    else:
        assert await retry_rate_limit(send) == 'ok'
        assert send.await_count == 4
        assert [call.args[0] for call in sleep.await_args_list] == [5, 10, 20]
    if interface == 'httpx':
        assert all(response.is_closed for response in responses[: send.await_count])
