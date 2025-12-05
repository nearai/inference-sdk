from dataclasses import dataclass

from .attestation_common import TcbInfo


@dataclass
class DomainInfo:
    tcb_info: TcbInfo | str


@dataclass
class DomainAttestation:
    intel_quote: str
    domain: str
    cert: str
    acme_account: str
    sha256sum: str
    info: DomainInfo


