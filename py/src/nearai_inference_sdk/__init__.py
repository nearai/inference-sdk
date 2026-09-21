"""Verification helpers for NEAR AI Cloud attestations and signatures."""

from .core.attestation_gateway import verify_gateway_attestation
from .core.attestation_model import verify_model_attestation
from .core.chat import verify_gateway_response, verify_model_response
from .core.e2ee_request import prepare_e2ee_chat_request
from .core.inference_client import InferenceClient
from .core.pinned_tls import create_pinned_tls_client
from .types.e2ee import E2eeModelKey, PreparedE2eeChatRequest
from .types.inference_client import (
    DeploymentPolicy,
    GatewayVerificationOptions,
    ModelVerificationOptions,
    VerifiedCompletionReceipt,
    VerifiedGatewayCompletionReceipt,
    VerifiedModelCompletionReceipt,
)
from .core.cloud_api import (
    AttestationClient,
    find_model_attestation_for_signature,
)
from .core.provenance import (
    fetch_image_provenance,
    verify_deployment_image_provenance,
    verify_image_provenance,
)
from .types.provenance import ImageProvenancePolicy, VerifiedImageProvenance
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
    GpuEvidenceVerifier,
    MeasuredDeployment,
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    ModelClientBinding,
    RuntimeMeasurements,
    TdxQuoteVerificationResult,
    TdxQuoteVerifier,
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
from .utils.intel import create_tdx_quote_verifier
from .utils.nvidia import create_gpu_evidence_verifier


__all__ = [
    'DEFAULT_NEAR_AI_CLOUD_BASE_URL',
    'NO_ALIASING_HEADER',
    'AttestationClient',
    'InferenceClient',
    'create_pinned_tls_client',
    'prepare_e2ee_chat_request',
    'E2eeModelKey',
    'PreparedE2eeChatRequest',
    'DeploymentPolicy',
    'GatewayVerificationOptions',
    'ModelVerificationOptions',
    'VerifiedCompletionReceipt',
    'VerifiedGatewayCompletionReceipt',
    'VerifiedModelCompletionReceipt',
    'find_model_attestation_for_signature',
    'verify_model_attestation',
    'verify_gateway_attestation',
    'verify_model_response',
    'verify_gateway_response',
    'create_tdx_quote_verifier',
    'create_gpu_evidence_verifier',
    'fetch_image_provenance',
    'verify_deployment_image_provenance',
    'verify_image_provenance',
    'ImageProvenancePolicy',
    'VerifiedImageProvenance',
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
    'TdxQuoteVerifier',
    'GpuEvidenceVerifier',
    'DeploymentVerifier',
    'TdxQuoteVerificationResult',
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
