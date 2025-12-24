from __future__ import annotations

from pydantic import BaseModel

from .attestation_common import TcbInfo


class DomainAttestation(BaseModel):
    intel_quote: str
    domain: str
    cert: str
    acme_account: str
    sha256sum: str
    info: DomainInfo


class DomainInfo(BaseModel):
    tcb_info: TcbInfo | str


class VerifyDomainAttestationConfig(BaseModel):
    image_names_of_sigstore_hash: list[str]
