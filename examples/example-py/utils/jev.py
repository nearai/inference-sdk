"""Reusable configuration for the verified official Jev SDK example."""

from contextlib import asynccontextmanager
from urllib.parse import urljoin, urlsplit

import httpx2
from nearai_inference_sdk import (
    InferenceClient,
    ModelAttestationPolicy,
    ModelVerificationOptions,
)
from typesafe_sdk import AsyncTypeSafeClient, RetryPolicy


@asynccontextmanager
async def verified_jev_clients(
    api_key: str,
    *,
    base_url: str,
    signing_algo: str = 'ed25519',
    expected_kind: str = 'gateway',
):
    if not urlsplit(base_url).path.rstrip('/').endswith('/v1'):
        raise ValueError('The Jev example requires a NEAR base URL ending in /v1/.')
    async with (
        InferenceClient(
            api_key,
            base_url=base_url,
            signing_algo=signing_algo,
            e2ee=False,
            ohttp=False,
            model_verification=ModelVerificationOptions(policy=ModelAttestationPolicy())
            if expected_kind == 'provider_tee'
            else None,
        ) as inference,
        AsyncTypeSafeClient(
            api_key=api_key,
            base_url=urljoin(inference.base_url, '../'),
            http_client=inference.httpx2_client,
            compression=False,
            retry=RetryPolicy(max_retries=0),
            timeout=120,
        ) as jev,
    ):
        yield inference, jev


def receipt_id(response: httpx2.Response) -> str:
    value = response.headers.get('x-generation-id')
    if not value:
        raise ValueError('Missing System One receipt ID.')
    return value
