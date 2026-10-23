"""Reusable configuration for the verified official Jev SDK example."""

from contextlib import asynccontextmanager
from urllib.parse import urljoin, urlsplit

import httpx2
from nearai_inference_sdk import InferenceClient
from nearai_inference_sdk.integrations.jev import create_jev_http_client
from typesafe_sdk import AsyncTypeSafeClient, RetryPolicy


@asynccontextmanager
async def verified_jev_clients(api_key: str, *, base_url: str):
    if not urlsplit(base_url).path.rstrip('/').endswith('/v1'):
        raise ValueError('The Jev example requires a NEAR base URL ending in /v1/.')
    async with (
        InferenceClient(
            api_key, base_url=base_url, e2ee=False, ohttp=False
        ) as inference,
        AsyncTypeSafeClient(
            api_key=api_key,
            base_url=urljoin(inference.base_url, '../'),
            http_client=create_jev_http_client(inference),
            compression=False,
            retry=RetryPolicy(max_retries=0),
            timeout=60,
        ) as jev,
    ):
        yield inference, jev


def receipt_id(response: httpx2.Response) -> str:
    value = response.headers.get('x-generation-id')
    if not value:
        raise ValueError('Missing System One receipt ID.')
    return value
