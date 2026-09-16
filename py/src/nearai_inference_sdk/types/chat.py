"""Completion-signature types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .attestation_common import SigningIdentity


CompletionSignatureKind = Literal['provider_tee', 'gateway']


@dataclass(frozen=True, kw_only=True)
class CompletionSignatureReference:
    kind: CompletionSignatureKind
    signer: SigningIdentity


@dataclass(frozen=True, kw_only=True)
class CompletionSignature(CompletionSignatureReference):
    """A Cloud API completion signature with an explicit trust boundary."""

    signed_text: str
    signature: str
