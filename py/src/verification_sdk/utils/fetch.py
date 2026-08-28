"""Minimal asynchronous HTTP transport used by the default adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

import aiohttp


@dataclass(frozen=True, kw_only=True)
class FetchResponse:
    status: int
    body: bytes

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self) -> str:
        return self.body.decode('utf-8')


async def fetch(
    url: str,
    *,
    method: str = 'GET',
    data: str | bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> FetchResponse:
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=client_timeout) as session:
        async with session.request(method, url, data=data, headers=headers) as response:
            return FetchResponse(status=response.status, body=await response.read())
