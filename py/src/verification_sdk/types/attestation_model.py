from __future__ import annotations

from pydantic import BaseModel

from .attestation_common import TcbInfo, SigningAlgo


class ModelAttestation(BaseModel):
    request_nonce: str
    signing_algo: SigningAlgo
    signing_address: str
    intel_quote: str
    nvidia_payload: str
    info: ModelInfo


class ModelInfo(BaseModel):
    tcb_info: TcbInfo | str


class ModelAttestationReport(BaseModel):
    all_attestations: list[ModelAttestation]


class VerifyModelAttestationConfig(BaseModel):
    image_names_of_sigstore_hash: list[str]
