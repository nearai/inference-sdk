from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from pydantic import BaseModel

from .attestation_common import TcbInfo
from .chat import SigningAlgo


@dataclass
class GatewayAttestation(BaseModel):
    request_nonce: str
    intel_quote: str
    info: GatewayInfo
    vpc: VpcInfo
    signing_algo: Optional[SigningAlgo] = None
    signing_address: Optional[str] = None


@dataclass
class GatewayInfo(BaseModel):
    tcb_info: TcbInfo | str


@dataclass
class VpcInfo(BaseModel):
    vpc_server_app_id: str
    vpc_hostname: str

