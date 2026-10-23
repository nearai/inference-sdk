"""HTTPX2 types over the shared verified HTTPX request pipeline."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

import httpx
import httpx2

if TYPE_CHECKING:
    from ..core.inference_client import _VerifiedInferenceClient


@contextmanager
def _httpx2_errors(request: httpx2.Request) -> Iterator[None]:
    try:
        yield
    except httpx.RequestError as error:
        error_type = getattr(httpx2, type(error).__name__, httpx2.RequestError)
        raise error_type(str(error), request=request) from error


class _RequestStream(httpx.AsyncByteStream):
    def __init__(self, stream: httpx2.AsyncByteStream) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class _ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, response: httpx.Response, request: httpx2.Request) -> None:
        self._response = response
        self._request = request

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            with _httpx2_errors(self._request):
                async for chunk in self._response.aiter_raw():
                    yield chunk
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        with _httpx2_errors(self._request):
            await self._response.aclose()


class _InferenceTransport(httpx2.AsyncBaseTransport):
    def __init__(self, owner: _VerifiedInferenceClient) -> None:
        self._owner = owner

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        native = httpx.Request(
            request.method,
            str(request.url),
            headers=request.headers.raw,
            stream=_RequestStream(request.stream),
            extensions=dict(request.extensions),
        )
        with _httpx2_errors(request):
            response = await self._owner.send(native)
            headers = response.headers.raw
            try:
                if response.is_stream_consumed:
                    # Buffered HTTPX content has already been decoded.
                    headers = [
                        (name, value)
                        for name, value in headers
                        if name.lower() not in (b'content-encoding', b'content-length')
                    ]
                    return httpx2.Response(
                        response.status_code,
                        headers=headers,
                        content=response.content,
                        extensions=dict(response.extensions),
                        request=request,
                    )
                return httpx2.Response(
                    response.status_code,
                    headers=headers,
                    stream=_ResponseStream(response, request),
                    extensions=dict(response.extensions),
                    request=request,
                )
            except BaseException:
                await response.aclose()
                raise
            finally:
                if response.is_stream_consumed:
                    await response.aclose()


def _create_httpx2_client(owner: _VerifiedInferenceClient) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=_InferenceTransport(owner), timeout=None)
