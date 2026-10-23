"""Jev's HTTPX2 boundary over the verified HTTPX System One transport."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import httpx2

from ..utils.errors import api_failure

if TYPE_CHECKING:
    from ..core.inference_client import InferenceClient


class _JevTransport(httpx2.AsyncBaseTransport):
    def __init__(self, owner: InferenceClient) -> None:
        self._owner = owner

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        expected = httpx2.URL(self._owner.base_url).join('systemone')
        if request.method != 'POST' or request.url.copy_with(query=None) != expected:
            raise api_failure('api.invalid_input', {'resource': 'systemone'})
        native = httpx.Request(
            request.method,
            str(request.url),
            headers=request.headers.raw,
            content=await request.aread(),
            extensions=dict(request.extensions),
        )
        response = await self._owner.send(native)
        try:
            return httpx2.Response(
                response.status_code,
                headers=response.headers.raw,
                content=await response.aread(),
                extensions=dict(response.extensions),
                request=request,
            )
        finally:
            await response.aclose()


def _create_jev_http_client(owner: InferenceClient) -> httpx2.AsyncClient:
    """Create the borrowed adapter exposed by InferenceClient.jev_http_client."""
    return httpx2.AsyncClient(transport=_JevTransport(owner), timeout=None)
