"""Raw model attestation evidence returned by NEAR AI Cloud."""

from __future__ import annotations

from dataclasses import dataclass

from .attestation_common import AttestationEvidence, SigningIdentity
from .compose_manager import ComposeManagerAttestation


@dataclass(frozen=True, kw_only=True)
class ModelAttestation(AttestationEvidence):
    """A model-serving TEE attestation."""

    reported_quote_data: str | None = None
    nvidia_payload: str | None = None
    signing_public_key: str | None = None
    compose_manager_attestation: ComposeManagerAttestation | None = None


__all__ = ['ModelAttestation', 'SigningIdentity']
