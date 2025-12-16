from __future__ import annotations

from pydantic import BaseModel

from .attestation_common import TcbInfo, SigningAlgo
from .attestation_model import ModelAttestation


class GatewayAttestation(BaseModel):
    request_nonce: str
    intel_quote: str
    info: GatewayInfo
    vpc: VpcInfo
    signing_algo: SigningAlgo | None = None
    signing_address: str | None = None


class GatewayInfo(BaseModel):
    tcb_info: TcbInfo | str


class VpcInfo(BaseModel):
    vpc_server_app_id: str
    vpc_hostname: str


class GatewayAttestationReport(BaseModel):
    gateway_attestation: GatewayAttestation
    model_attestations: list[ModelAttestation] | None = None
