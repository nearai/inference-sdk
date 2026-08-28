"""Verification helpers for NEAR AI Cloud attestations and signatures."""

from .core.attestation_gateway import verify_gateway_attestation
from .core.attestation_model import verify_model_attestation
from .core.chat import verify_gateway_response, verify_model_response
from .core.cloud_api import (
    fetch_completion_signature,
    fetch_gateway_attestation,
    fetch_model_attestation_for_signature,
    fetch_model_attestations,
    find_model_attestation_for_signature,
    lookup_completion_signature,
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
    CompletionSignatureLookup,
    CompletionSignatureReference,
    SignatureUnavailable,
)
from .types.cloud_api import (
    DEFAULT_NEAR_AI_CLOUD_BASE_URL,
    NO_ALIASING_HEADER,
    FetchedGatewayAttestation,
    FetchedModelAttestation,
    FetchedModelAttestations,
    GatewayAttestationResponse,
    GatewayAttestationTransport,
)
from .types.verification import (
    AttestationPolicy,
    AttestationVerifiers,
    DeploymentVerifier,
    GatewayTlsBinding,
    MeasuredDeployment,
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    ModelTlsBinding,
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
    'fetch_completion_signature',
    'fetch_gateway_attestation',
    'fetch_model_attestation_for_signature',
    'fetch_model_attestations',
    'find_model_attestation_for_signature',
    'lookup_completion_signature',
    'verify_model_attestation',
    'verify_gateway_attestation',
    'verify_model_response',
    'verify_gateway_response',
    'GatewayAttestationResponse',
    'GatewayAttestationTransport',
    'FetchedModelAttestation',
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
    'CompletionSignatureLookup',
    'SignatureUnavailable',
    'AttestationPolicy',
    'ModelAttestationPolicy',
    'AttestationVerifiers',
    'ModelAttestationVerifiers',
    'QuoteVerifier',
    'NvidiaEvidenceVerifier',
    'DeploymentVerifier',
    'QuoteVerificationResult',
    'RuntimeMeasurements',
    'MeasuredDeployment',
    'ModelTlsBinding',
    'GatewayTlsBinding',
    'VerifiedAttestationEvidence',
    'VerifiedModelAttestation',
    'VerifiedGatewayAttestation',
    'ApiError',
    'ApiFailure',
    'VerificationError',
    'VerificationFailure',
]
