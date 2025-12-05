from dataclasses import dataclass
from typing import Optional

from .attestation_common import TcbInfo
from .chat import SigningAlgo


@dataclass
class GatewayVpcInfo:
    vpc_server_app_id: str
    vpc_hostname: str


@dataclass
class GatewayInfo:
    tcb_info: TcbInfo | str


@dataclass
class GatewayAttestation:
    request_nonce: str
    intel_quote: str
    info: GatewayInfo
    vpc: GatewayVpcInfo
    signing_algo: Optional[SigningAlgo] = None
    signing_address: Optional[str] = None


@dataclass
class GatewayAttestationWithDomain(GatewayAttestation):
    domain: str = ""


