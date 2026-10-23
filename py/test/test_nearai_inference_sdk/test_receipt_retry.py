from unittest.mock import AsyncMock

import pytest

from e2e import helpers
from nearai_inference_sdk.utils.errors import api_failure, verification_failure


async def test_unavailable_receipt_recovers_without_repeating_inference(monkeypatch):
    wait = AsyncMock()
    monkeypatch.setattr(helpers.asyncio, 'sleep', wait)
    lookup = AsyncMock(
        side_effect=[
            api_failure('api.completion_signature_unavailable'),
            api_failure('api.completion_signature_unavailable'),
            'verified',
        ]
    )
    assert await helpers.retry_receipt(lookup) == 'verified'
    assert lookup.await_count == 3
    assert [call.args[0] for call in wait.await_args_list] == [0.5, 1]


async def test_receipt_retry_is_bounded_and_rejects_crypto_failures(monkeypatch):
    wait = AsyncMock()
    monkeypatch.setattr(helpers.asyncio, 'sleep', wait)
    unavailable = api_failure('api.completion_signature_unavailable')
    lookup = AsyncMock(side_effect=unavailable)
    with pytest.raises(type(unavailable)):
        await helpers.retry_receipt(lookup)
    assert lookup.await_count == 5
    assert [call.args[0] for call in wait.await_args_list] == [0.5, 1, 2, 4]
    wait.reset_mock()
    invalid = verification_failure('signature.payload_mismatch')
    lookup = AsyncMock(side_effect=invalid)
    with pytest.raises(type(invalid)):
        await helpers.retry_receipt(lookup)
    assert lookup.await_count == 1
    wait.assert_not_awaited()
