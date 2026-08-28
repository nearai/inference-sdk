"""Raw Gateway attestation evidence returned by NEAR AI Cloud."""

from __future__ import annotations

from dataclasses import dataclass, field

from .attestation_common import AttestationEvidence


@dataclass(frozen=True, kw_only=True)
class GatewayAttestation(AttestationEvidence):
    """A NEAR AI Cloud Gateway TEE attestation."""

    reported_quote_data: str = field()
