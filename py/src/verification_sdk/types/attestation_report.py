from typing import Optional
from pydantic import BaseModel

from .attestation_gateway import GatewayAttestation
from .attestation_model import ModelAttestation


class AttestationReport(BaseModel):
    gateway_attestation: GatewayAttestation
    model_attestations: Optional[list[ModelAttestation]] = None

