from dataclasses import dataclass

from .attestation_common import TcbInfo
from .chat import SigningAlgo


@dataclass
class ModelInfo:
    tcb_info: TcbInfo | str


@dataclass
class ModelAttestation:
    request_nonce: str
    signing_algo: SigningAlgo
    signing_address: str
    intel_quote: str
    nvidia_payload: str
    info: ModelInfo


