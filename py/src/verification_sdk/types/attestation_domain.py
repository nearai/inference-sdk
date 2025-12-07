from __future__ import annotations
from dataclasses import dataclass
from pydantic import BaseModel

from .attestation_common import TcbInfo


@dataclass
class DomainAttestation(BaseModel):
    intel_quote: str
    domain: str
    cert: str
    acme_account: str
    sha256sum: str
    info: DomainInfo


@dataclass
class DomainInfo(BaseModel):
    tcb_info: TcbInfo | str

