"""
Python verification SDK mirroring the NEAR AI Cloud JS SDK.

The public surface roughly matches `js/src/index.ts`:

- verify_gateway_attestation
- verify_model_attestation
- verify_domain_attestation
- verify_chat
- verify_signing_address
- VerificationError
"""

from .core.attestation_gateway import verify_gateway_attestation
from .core.attestation_model import verify_model_attestation
from .core.attestation_domain import verify_domain_attestation
from .core.chat import verify_chat, verify_signing_address
from .types.attestation_gateway import GatewayAttestation
from .types.attestation_model import ModelAttestation
from .types.attestation_domain import DomainAttestation
from .types.attestation_report import AttestationReport
from .types.chat import Chat, ChatSignature, SigningAlgo
from .utils.errors import VerificationError

__all__ = [
    "verify_gateway_attestation",
    "verify_model_attestation",
    "verify_domain_attestation",
    "verify_chat",
    "verify_signing_address",
    "GatewayAttestation",
    "ModelAttestation",
    "DomainAttestation",
    "AttestationReport",
    "Chat",
    "ChatSignature",
    "SigningAlgo",
    "VerificationError",
]

