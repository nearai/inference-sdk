from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel

from verification_sdk.types.attestation_gateway import GatewayAttestation
from verification_sdk.types.attestation_model import ModelAttestation


@dataclass
class TcbInfo(BaseModel):
    app_compose: str


@dataclass
class AttestationReport(BaseModel):
    gateway_attestation: GatewayAttestation
    model_attestations: Optional[list[ModelAttestation]]

