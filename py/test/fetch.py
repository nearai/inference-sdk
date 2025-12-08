import json
import aiohttp

from typing import Optional, Literal, Any
from dataclasses import dataclass


@dataclass
class FetchResponse:
    status: int
    data: Optional[bytes] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def json(self) -> Any:
        if self.data is None:
            raise ValueError('Response data is None')
        return json.loads(self.data)

    def text(self) -> str:
        if self.data is None:
            raise ValueError('Response data is None')
        return self.data.decode()

    def bytes(self) -> bytes:
        if self.data is None:
            raise ValueError('Response data is None')
        return self.data


Method = Literal['GET', 'POST', 'HEAD']


async def fetch(
    url: str,
    method: Method = 'GET',
    data: Optional[Any] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: Optional[float] = None,
) -> FetchResponse:
    timeout = aiohttp.ClientTimeout(total=timeout) if timeout else None

    async with aiohttp.ClientSession(timeout=timeout) as session:
        if method == 'GET':
            async with session.get(url, headers=headers) as response:
                data = await response.read()
                fetch_response = FetchResponse(status=response.status, data=data)
        elif method == 'POST':
            async with session.post(url, data=data, headers=headers) as response:
                data = await response.read()
                fetch_response = FetchResponse(status=response.status, data=data)
        elif method == 'HEAD':
            async with session.head(url, headers=headers) as response:
                fetch_response = FetchResponse(status=response.status)
        else:
            raise ValueError(f'Unsupported method: {method}')

    return fetch_response
