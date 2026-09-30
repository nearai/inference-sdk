"""Inputs and prepared HTTP messages for standalone Chat E2EE."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx

from .attestation_common import SigningAlgo


@dataclass(frozen=True, kw_only=True)
class E2eeModelKey:
    """A model public key obtained from verified attestation evidence."""

    signing_algo: SigningAlgo
    public_key: str


@dataclass(frozen=True, kw_only=True)
class PreparedE2eeChatRequest:
    """An encrypted request and the matching JSON/SSE response decryptor."""

    request: httpx.Request
    decrypt_response: Callable[[httpx.Response], Awaitable[httpx.Response]]
