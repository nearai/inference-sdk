from __future__ import annotations

from types import SimpleNamespace

import aiohttp
import pytest

from verifiable_ai_sdk.utils import fetch as fetch_module


async def test_gateway_response_captures_peer_before_aiohttp_releases_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = SimpleNamespace(transport=object())
    expected_fingerprint = 'peer-spki-fingerprint'

    async def parent_start(
        response: aiohttp.ClientResponse,
        received_connection: object,
    ) -> aiohttp.ClientResponse:
        assert received_connection is connection
        assert response.peer_spki_fingerprint == expected_fingerprint
        return response

    monkeypatch.setattr(
        fetch_module,
        '_peer_spki_fingerprint',
        lambda transport: expected_fingerprint,
    )
    monkeypatch.setattr(aiohttp.ClientResponse, 'start', parent_start)
    response = object.__new__(fetch_module._GatewayAttestationResponse)
    await response.start(connection)
