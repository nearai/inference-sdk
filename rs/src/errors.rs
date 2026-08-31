use crate::types::{CompletionSignatureKind, SigningAlgo, TcbStatus};
use thiserror::Error;

/// Cloud API resource involved in an API failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiResource {
    ModelAttestation,
    GatewayAttestation,
    CompletionSignature,
}

/// The request stage that failed before NEAR AI Cloud returned a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiTransportReason {
    Request,
    ResponseBody,
}

impl std::fmt::Display for ApiTransportReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Request => "request",
            Self::ResponseBody => "response body",
        })
    }
}

impl std::fmt::Display for ApiResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::ModelAttestation => "model attestation",
            Self::GatewayAttestation => "gateway attestation",
            Self::CompletionSignature => "completion signature",
        };
        formatter.write_str(value)
    }
}

/// Failures while calling NEAR AI Cloud or selecting evidence returned by it.
/// These are deliberately distinct from local input and verification failures.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Cloud API {resource} {reason} failed")]
    Transport {
        resource: ApiResource,
        reason: ApiTransportReason,
    },

    #[error("Cloud API {resource} returned HTTP {status}")]
    HttpStatus { resource: ApiResource, status: u16 },

    #[error("Cloud API {resource} returned invalid JSON")]
    InvalidJson { resource: ApiResource },

    #[error("Cloud API response has an invalid {path}: expected {expected}")]
    InvalidResponse { path: String, expected: String },

    #[error("{resource} response nonce does not match the request")]
    NonceMismatch { resource: ApiResource },

    #[error("Cloud API returned {actual_count} model attestations; expected exactly one")]
    UnexpectedModelAttestationCount { actual_count: usize },

    #[error("Cloud API returned no model attestation for the requested signer")]
    ModelAttestationSignerNotFound,

    #[error(
        "Cloud API returned {matching_count} model attestations for the requested signer ({total_count} total)"
    )]
    AmbiguousModelAttestationSigner {
        matching_count: usize,
        total_count: usize,
    },

    #[error("Cloud API did not provide a completion signature ({provider_error_code})")]
    CompletionSignatureUnavailable { provider_error_code: String },
}

impl ApiError {
    /// Stable machine-readable error code shared with the TypeScript SDK.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Transport { .. } => "api.transport_failed",
            Self::HttpStatus { .. } => "api.http_status",
            Self::InvalidJson { .. } => "api.invalid_json",
            Self::InvalidResponse { .. } => "api.invalid_response",
            Self::NonceMismatch { .. } => "api.nonce_mismatch",
            Self::UnexpectedModelAttestationCount { .. } => {
                "api.unexpected_model_attestation_count"
            }
            Self::ModelAttestationSignerNotFound => "api.model_attestation_signer_not_found",
            Self::AmbiguousModelAttestationSigner { .. } => {
                "api.ambiguous_model_attestation_signer"
            }
            Self::CompletionSignatureUnavailable { .. } => "api.completion_signature_unavailable",
        }
    }

    /// Whether retrying the same operation may reasonably succeed.
    pub fn retryable(&self) -> bool {
        match self {
            Self::Transport { .. } => true,
            Self::HttpStatus { resource, status } => {
                (*resource == ApiResource::CompletionSignature && *status == 404)
                    || *status == 408
                    || *status == 425
                    || *status == 429
                    || *status >= 500
            }
            _ => false,
        }
    }
}

/// Local attestation, policy, measurement, or response-signature failure.
///
/// Consumers should branch on [`Self::code`] rather than the display message.
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("invalid input {field}: {reason}")]
    InvalidInput { field: String, reason: String },

    #[error("Intel quote collateral is unavailable")]
    QuoteCollateralUnavailable,

    #[error("Intel quote verification failed: {reason}")]
    QuoteVerificationFailed { reason: &'static str },

    #[error("Intel quote verifier returned an invalid result: {reason}")]
    QuoteInvalidResult { reason: String },

    #[error("Intel quote report type is unsupported; expected TD10")]
    QuoteUnsupportedReportType,

    #[error("quote was created with debug enabled")]
    DebugEnabled,

    #[error("TCB status {actual:?} is not accepted by policy")]
    TcbStatusNotAllowed {
        actual: TcbStatus,
        accepted: Vec<TcbStatus>,
        advisory_ids: Vec<String>,
    },

    #[error("GPU evidence is required by policy but was not provided")]
    GpuEvidenceRequired,

    #[error("Gateway TLS binding is required by policy")]
    TlsBindingRequired,

    #[error("attestation nonce binding did not match ({binding})")]
    NonceMismatch { binding: &'static str },

    #[error("quote report data is invalid: {reason}")]
    ReportDataInvalid { reason: &'static str },

    #[error("quote report data binding did not match ({binding})")]
    ReportDataMismatch { binding: &'static str },

    #[error("attestation TLS SPKI fingerprint does not match the observed peer")]
    SpkiFingerprintMismatch,

    #[error("event log is invalid at {path}: {reason}")]
    EventLogInvalid { path: String, reason: &'static str },

    #[error("RTMR3 replay did not match: {reason}")]
    Rtmr3Mismatch { reason: &'static str },

    #[error("MRCONFIGID is invalid: {reason}")]
    MrConfigIdInvalid { reason: &'static str },

    #[error("app compose does not match the MRCONFIGID measurement")]
    AppComposeMrConfigIdMismatch,

    #[error("NVIDIA payload is invalid: {reason}")]
    GpuPayloadInvalid { reason: &'static str },

    #[error("NVIDIA NRAS request failed: {reason}")]
    NrasRequestFailed {
        reason: &'static str,
        status: Option<u16>,
        retryable: bool,
    },

    #[error("NVIDIA NRAS response is invalid: {reason}")]
    NrasResponseInvalid { reason: &'static str },

    #[error("NVIDIA attestation was rejected ({origin})")]
    GpuAttestationRejected { origin: &'static str },

    #[error("deployment provenance verifier rejected the measured deployment")]
    DeploymentProvenanceRejected,

    #[error("completion signature kind {actual:?} cannot be used here; expected {expected:?}")]
    SignatureKindMismatch {
        expected: CompletionSignatureKind,
        actual: CompletionSignatureKind,
    },

    #[error("completion signed payload does not match ({reason})")]
    SignaturePayloadMismatch { reason: &'static str },

    #[error("completion signature format is invalid for {field}: {reason}")]
    SignatureFormatInvalid {
        field: &'static str,
        reason: &'static str,
    },

    #[error("completion signature is invalid for {signing_algo:?}")]
    SignatureInvalid { signing_algo: SigningAlgo },

    #[error("completion signature signer does not match verified attestation evidence")]
    SignatureSignerMismatch,
}

impl VerificationError {
    /// Stable machine-readable error code shared with the TypeScript SDK.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput { .. } => "input.invalid",
            Self::QuoteCollateralUnavailable => "quote.collateral_unavailable",
            Self::QuoteVerificationFailed { .. } => "quote.verification_failed",
            Self::QuoteInvalidResult { .. } => "quote.invalid_result",
            Self::QuoteUnsupportedReportType => "quote.unsupported_report_type",
            Self::DebugEnabled => "policy.debug_enabled",
            Self::TcbStatusNotAllowed { .. } => "policy.tcb_status_not_allowed",
            Self::GpuEvidenceRequired => "policy.gpu_evidence_required",
            Self::TlsBindingRequired => "policy.tls_binding_required",
            Self::NonceMismatch { .. } => "binding.nonce_mismatch",
            Self::ReportDataInvalid { .. } => "binding.report_data_invalid",
            Self::ReportDataMismatch { .. } => "binding.report_data_mismatch",
            Self::SpkiFingerprintMismatch => "binding.spki_fingerprint_mismatch",
            Self::EventLogInvalid { .. } => "measurement.event_log_invalid",
            Self::Rtmr3Mismatch { .. } => "measurement.rtmr3_mismatch",
            Self::MrConfigIdInvalid { .. } => "measurement.mrconfigid_invalid",
            Self::AppComposeMrConfigIdMismatch => "measurement.app_compose_mrconfigid_mismatch",
            Self::GpuPayloadInvalid { .. } => "gpu.payload_invalid",
            Self::NrasRequestFailed { .. } => "gpu.nras_request_failed",
            Self::NrasResponseInvalid { .. } => "gpu.nras_response_invalid",
            Self::GpuAttestationRejected { .. } => "gpu.attestation_rejected",
            Self::DeploymentProvenanceRejected => "provenance.verification_failed",
            Self::SignatureKindMismatch { .. } => "signature.kind_mismatch",
            Self::SignaturePayloadMismatch { .. } => "signature.payload_mismatch",
            Self::SignatureFormatInvalid { .. } => "signature.format_invalid",
            Self::SignatureInvalid { .. } => "signature.invalid",
            Self::SignatureSignerMismatch => "signature.signer_mismatch",
        }
    }

    /// True only for failures where a retry might change the result.
    pub const fn retryable(&self) -> bool {
        match self {
            Self::QuoteCollateralUnavailable => true,
            Self::NrasRequestFailed { retryable, .. } => *retryable,
            _ => false,
        }
    }
}

/// A small convenience wrapper for APIs which can fail while both fetching
/// Cloud evidence and applying a local signature rule.
#[derive(Debug, Error)]
pub enum SdkError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Verification(#[from] VerificationError),
}

impl SdkError {
    pub fn retryable(&self) -> bool {
        match self {
            Self::Api(error) => error.retryable(),
            Self::Verification(error) => error.retryable(),
        }
    }
}
