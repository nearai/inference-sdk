"""Verification helpers for NEAR AI Cloud attestations and signatures."""

from .core.attestation_gateway import verify_gateway_attestation
from .core.attestation_model import verify_model_attestation
from .core.chat import verify_gateway_response, verify_model_response
from .core.cloud_api import (
    AttestationClient,
    find_model_attestation_for_signature,
)
from .types.attestation_common import (
    AttestationEvidence,
    AttestationEventLog,
    SigningAlgo,
    SigningIdentity,
    TcbStatus,
)
from .types.attestation_gateway import GatewayAttestation
from .types.attestation_model import ModelAttestation
from .types.chat import (
    CompletionSignature,
    CompletionSignatureKind,
    CompletionSignatureReference,
)
from .types.cloud_api import (
    DEFAULT_NEAR_AI_CLOUD_BASE_URL,
    NO_ALIASING_HEADER,
    FetchedGatewayAttestation,
    FetchedModelAttestations,
)
from .types.verification import (
    AttestationPolicy,
    AttestationVerifiers,
    DeploymentVerifier,
    GatewayClientBinding,
    GatewayTlsBinding,
    MeasuredDeployment,
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    ModelClientBinding,
    NvidiaEvidenceVerifier,
    QuoteVerificationResult,
    QuoteVerifier,
    RuntimeMeasurements,
    VerifiedAttestationEvidence,
    VerifiedGatewayAttestation,
    VerifiedModelAttestation,
)
from .utils.errors import (
    ApiError,
    ApiFailure,
    VerificationError,
    VerificationFailure,
)


__all__ = [
    'DEFAULT_NEAR_AI_CLOUD_BASE_URL',
    'NO_ALIASING_HEADER',
    'AttestationClient',
    'find_model_attestation_for_signature',
    'verify_model_attestation',
    'verify_gateway_attestation',
    'verify_model_response',
    'verify_gateway_response',
    'FetchedGatewayAttestation',
    'FetchedModelAttestations',
    'SigningAlgo',
    'SigningIdentity',
    'TcbStatus',
    'AttestationEventLog',
    'AttestationEvidence',
    'ModelAttestation',
    'GatewayAttestation',
    'CompletionSignature',
    'CompletionSignatureKind',
    'CompletionSignatureReference',
    'AttestationPolicy',
    'ModelAttestationPolicy',
    'AttestationVerifiers',
    'ModelAttestationVerifiers',
    'ModelClientBinding',
    'QuoteVerifier',
    'NvidiaEvidenceVerifier',
    'DeploymentVerifier',
    'QuoteVerificationResult',
    'RuntimeMeasurements',
    'MeasuredDeployment',
    'GatewayClientBinding',
    'GatewayTlsBinding',
    'VerifiedAttestationEvidence',
    'VerifiedModelAttestation',
    'VerifiedGatewayAttestation',
    'ApiError',
    'ApiFailure',
    'VerificationError',
    'VerificationFailure',
]
