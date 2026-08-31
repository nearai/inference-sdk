"""Raw Gateway attestation evidence returned by NEAR AI Cloud."""

from __future__ import annotations

from dataclasses import dataclass

from .attestation_common import AttestationEvidence


@dataclass(frozen=True, kw_only=True)
class GatewayAttestation(AttestationEvidence):
    """A NEAR AI Cloud Gateway TEE attestation."""

    #: Present only when the evidence request enabled TLS binding.
    tls_spki_fingerprint: str | None = None
    reported_quote_data: str
