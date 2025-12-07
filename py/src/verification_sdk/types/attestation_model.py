from __future__ import annotations
from dataclasses import dataclass
from pydantic import BaseModel

from .attestation_common import TcbInfo
from .chat import SigningAlgo


@dataclass
class ModelAttestation(BaseModel):
    request_nonce: str
    signing_algo: SigningAlgo
    signing_address: str
    intel_quote: str
    nvidia_payload: str
    info: ModelInfo


@dataclass
class ModelInfo(BaseModel):
    tcb_info: TcbInfo | str

