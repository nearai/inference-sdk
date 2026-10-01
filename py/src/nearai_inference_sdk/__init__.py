"""Verification helpers for NEAR AI Cloud attestations and signatures."""

from .core.attestation_direct import (
    verify_direct_model_attestation,
    verify_direct_model_attestations,
)
from .core.attestation_gateway import verify_gateway_attestation
from .core.attestation_model import verify_model_attestation
from .core.chat import verify_gateway_response, verify_model_response
from .core.cloud_api import (
    AttestationClient,
    find_model_attestation_for_signature,
)
from .core.compose_manager_provenance import (
    verify_compose_manager_deployment_image_provenance,
)
from .core.direct_api import DirectAttestationClient
from .core.direct_inference_client import (
    DirectInferenceClient,
    verify_direct_model_response,
)
from .core.e2ee_request import prepare_e2ee_chat_request
from .core.inference_client import InferenceClient
from .core.ohttp import create_ohttp_client
from .core.ohttp_attestation import verify_ohttp_key_config
from .core.pinned_tls import create_pinned_tls_client
from .core.provenance import (
    fetch_image_provenance,
    verify_deployment_image_provenance,
    verify_image_provenance,
)
from .types.attestation_common import (
    AttestationEventLog,
    AttestationEvidence,
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
    ModelMetadata,
)
from .types.compose_manager import (
    ComposeManagerAction,
    ComposeManagerAttestation,
    VerifiedComposeManagerAttestation,
)
from .types.direct import (
    DirectAttestationVerificationResult,
    DirectClientBinding,
    DirectModelAttestation,
    DirectModelVerificationOptions,
    DirectTlsBinding,
    FetchedDirectModelAttestations,
    VerifiedDirectCompletionResult,
    VerifiedDirectModelAttestation,
    VerifiedDirectModelAttestations,
)
from .types.e2ee import E2eeModelKey, PreparedE2eeChatRequest
from .types.inference_client import (
    AttestationVerificationResult,
    DeploymentPolicy,
    GatewayVerificationOptions,
    ModelVerificationOptions,
    VerifiedCompletionResult,
    VerifiedGatewayCompletionResult,
    VerifiedModelCompletionResult,
)
from .types.ohttp import OhttpAttestation
from .types.provenance import ImageProvenancePolicy, VerifiedImageProvenance
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
    'ApiError',
    'ApiFailure',
    'AttestationClient',
    'AttestationEventLog',
    'AttestationEvidence',
    'AttestationPolicy',
    'AttestationVerificationResult',
    'AttestationVerifiers',
    'CompletionSignature',
    'CompletionSignatureKind',
    'CompletionSignatureReference',
    'ComposeManagerAction',
    'ComposeManagerAttestation',
    'DeploymentPolicy',
    'DeploymentVerifier',
    'DirectAttestationClient',
    'DirectAttestationVerificationResult',
    'DirectClientBinding',
    'DirectInferenceClient',
    'DirectModelAttestation',
    'DirectModelVerificationOptions',
    'DirectTlsBinding',
    'E2eeModelKey',
    'FetchedDirectModelAttestations',
    'FetchedGatewayAttestation',
    'FetchedModelAttestations',
    'GatewayAttestation',
    'GatewayClientBinding',
    'GatewayTlsBinding',
    'GatewayVerificationOptions',
    'GpuEvidenceVerifier',
    'ImageProvenancePolicy',
    'InferenceClient',
    'MeasuredDeployment',
    'ModelAttestation',
    'ModelAttestationPolicy',
    'ModelAttestationVerifiers',
    'ModelClientBinding',
    'ModelMetadata',
    'ModelVerificationOptions',
    'OhttpAttestation',
    'PreparedE2eeChatRequest',
    'RuntimeMeasurements',
    'SigningAlgo',
    'SigningIdentity',
    'TcbStatus',
    'TdxQuoteVerificationResult',
    'TdxQuoteVerifier',
    'VerificationError',
    'VerificationFailure',
    'VerifiedAttestationEvidence',
    'VerifiedCompletionResult',
    'VerifiedComposeManagerAttestation',
    'VerifiedDirectCompletionResult',
    'VerifiedDirectModelAttestation',
    'VerifiedDirectModelAttestations',
    'VerifiedGatewayAttestation',
    'VerifiedGatewayCompletionResult',
    'VerifiedImageProvenance',
    'VerifiedModelAttestation',
    'VerifiedModelCompletionResult',
    'create_gpu_evidence_verifier',
    'create_ohttp_client',
    'create_pinned_tls_client',
    'create_tdx_quote_verifier',
    'fetch_image_provenance',
    'find_model_attestation_for_signature',
    'prepare_e2ee_chat_request',
    'verify_compose_manager_deployment_image_provenance',
    'verify_deployment_image_provenance',
    'verify_direct_model_attestation',
    'verify_direct_model_attestations',
    'verify_direct_model_response',
    'verify_gateway_attestation',
    'verify_gateway_response',
    'verify_image_provenance',
    'verify_model_attestation',
    'verify_model_response',
    'verify_ohttp_key_config',
]
