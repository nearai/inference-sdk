"""Completion signatures and exact completion bytes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .attestation_common import SigningIdentity


CompletionSignatureKind = Literal['provider_tee', 'gateway']


@dataclass(frozen=True, kw_only=True)
class CompletionBytes:
    request_body: bytes
    response_body: bytes


@dataclass(frozen=True, kw_only=True)
class CompletionSignatureReference:
    kind: CompletionSignatureKind
    signer: SigningIdentity


@dataclass(frozen=True, kw_only=True)
class CompletionSignature(CompletionSignatureReference):
    """A Cloud API completion signature with an explicit trust boundary."""

    signed_text: str
    signature: str


@dataclass(frozen=True, kw_only=True)
class SignatureUnavailable:
    error_code: str
    message: str


@dataclass(frozen=True, kw_only=True)
class CompletionSignatureLookup:
    """Either a found signature or the service's non-error unavailable state."""

    status: Literal['found', 'unavailable']
    signature: CompletionSignature | None = None
    unavailable: SignatureUnavailable | None = None
