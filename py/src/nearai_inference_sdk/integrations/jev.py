"""Jev's HTTPX2 boundary over the verified HTTPX System One transport."""

import httpx
import httpx2

from ..core.inference_client import InferenceClient
from ..utils.errors import api_failure


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


def create_jev_http_client(owner: InferenceClient) -> httpx2.AsyncClient:
    """Create a non-owning adapter for uncompressed, nonstreaming System One.

    Install the ``jev`` extra to import this module. Pass the adapter to Jev's
    ``AsyncTypeSafeClient`` with compression and retries disabled. Keep ``owner``
    open while sending requests and verifying receipts; closing this adapter
    does not close its owner. All network I/O and verification use HTTPX.
    """
    return httpx2.AsyncClient(transport=_JevTransport(owner), timeout=None)
