"""Raw model attestation evidence returned by NEAR AI Cloud."""

from __future__ import annotations

from dataclasses import dataclass

from .attestation_common import AttestationEvidence, SigningIdentity


@dataclass(frozen=True, kw_only=True)
class ModelAttestation(AttestationEvidence):
    """A model-serving TEE attestation."""

    reported_quote_data: str | None = None
    nvidia_payload: str | None = None


__all__ = ['ModelAttestation', 'SigningIdentity']
