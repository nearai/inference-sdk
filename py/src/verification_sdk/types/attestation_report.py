from dataclasses import dataclass
from typing import Optional
from pydantic import BaseModel

from .attestation_gateway import GatewayAttestation
from .attestation_model import ModelAttestation


@dataclass
class AttestationReport(BaseModel):
    gateway_attestation: GatewayAttestation
    model_attestations: Optional[list[ModelAttestation]]

