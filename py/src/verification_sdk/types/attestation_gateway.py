from __future__ import annotations
from typing import Optional
from pydantic import BaseModel

from .attestation_common import TcbInfo, SigningAlgo


class GatewayAttestation(BaseModel):
    request_nonce: str
    intel_quote: str
    info: GatewayInfo
    vpc: VpcInfo
    signing_algo: Optional[SigningAlgo] = None
    signing_address: Optional[str] = None


class GatewayInfo(BaseModel):
    tcb_info: TcbInfo | str


class VpcInfo(BaseModel):
    vpc_server_app_id: str
    vpc_hostname: str

