use crate::errors::VerificationError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Signature algorithms exposed by NEAR AI Cloud.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningAlgo {
    Ecdsa,
    Ed25519,
}

impl std::fmt::Display for SigningAlgo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ecdsa => formatter.write_str("ecdsa"),
            Self::Ed25519 => formatter.write_str("ed25519"),
        }
    }
}

/// Public identity of a key which signs a completion or attestation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SigningIdentity {
    pub signing_algo: SigningAlgo,
    pub signing_address: String,
}

/// dstack event-log data as returned by the attestation endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttestationEventLog {
    Json(String),
    Entries(Vec<Value>),
}

/// Evidence shared by NEAR model and Gateway attestations.
#[derive(Clone, Debug)]
pub struct AttestationEvidence {
    pub nonce: String,
    pub signer: SigningIdentity,
    pub intel_quote: String,
    pub event_log: AttestationEventLog,
    pub app_compose: String,
}

/// Raw model-serving TEE evidence returned through NEAR AI Cloud.
#[derive(Clone, Debug)]
pub struct ModelAttestation {
    pub evidence: AttestationEvidence,
    /// Optional server-declared value. An absent value becomes `None` at the
    /// Cloud API response boundary.
    pub declared_spki_fingerprint: Option<String>,
    /// Optional server-declared copy of quote report data. An absent value
    /// becomes `None` at the Cloud API response boundary.
    pub reported_quote_data: Option<String>,
    /// NVIDIA evidence is optional for model deployments which do not expose it.
    /// Absent evidence is represented as `None`.
    pub nvidia_payload: Option<String>,
}

/// Raw NEAR AI Cloud Gateway evidence.
#[derive(Clone, Debug)]
pub struct GatewayAttestation {
    pub evidence: AttestationEvidence,
    /// TLS SPKI fingerprint declared by the Gateway and authenticated by its
    /// quote.
    pub declared_spki_fingerprint: String,
    /// Gateway reports always advertise the quote report-data copy.
    pub reported_quote_data: String,
}

/// Intel TDX status returned by a quote verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TcbStatus {
    #[serde(rename = "UpToDate")]
    UpToDate,
    #[serde(rename = "SWHardeningNeeded")]
    SwHardeningNeeded,
    #[serde(rename = "ConfigurationNeeded")]
    ConfigurationNeeded,
    #[serde(rename = "ConfigurationAndSWHardeningNeeded")]
    ConfigurationAndSwHardeningNeeded,
    #[serde(rename = "OutOfDate")]
    OutOfDate,
    #[serde(rename = "OutOfDateConfigurationNeeded")]
    OutOfDateConfigurationNeeded,
    #[serde(rename = "Revoked")]
    Revoked,
    #[serde(rename = "Unknown")]
    Unknown,
}

/// Facts returned by a quote verifier before SDK policy and binding checks.
#[derive(Clone, Debug)]
pub struct QuoteVerificationResult {
    pub tcb_status: TcbStatus,
    pub advisory_ids: Vec<String>,
    pub debug_enabled: bool,
    pub report_data: Vec<u8>,
    pub mr_config_id: Vec<u8>,
    pub rt_mr3: Vec<u8>,
}

/// A caller-supplied Intel quote verifier. The SDK's default verifier uses
/// Intel DCAP through PCCS, but tests and specialized deployments can supply
/// their own implementation.
#[async_trait]
pub trait QuoteVerifier: Send + Sync {
    async fn verify(&self, intel_quote: &str)
        -> Result<QuoteVerificationResult, VerificationError>;
}

/// A caller-supplied NVIDIA evidence verifier. The default implementation
/// delegates to NRAS over HTTPS.
#[async_trait]
pub trait NvidiaEvidenceVerifier: Send + Sync {
    async fn verify(&self, nvidia_payload: &str) -> Result<(), VerificationError>;
}

/// A caller-owned deployment-provenance verifier. It receives measurements
/// that have already been authenticated by the Intel quote.
#[async_trait]
pub trait DeploymentVerifier: Send + Sync {
    async fn verify(&self, deployment: &MeasuredDeployment) -> Result<(), VerificationError>;
}

/// Internal quote policy shared by model and Gateway attestation verification.
#[derive(Clone, Debug, Default)]
pub(crate) struct AttestationPolicy {
    /// Defaults to `UpToDate` and `OutOfDate` when omitted.
    pub accepted_tcb_statuses: Option<Vec<TcbStatus>>,
}

/// Model-specific policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GpuEvidenceRequirement {
    /// Verify a supplied payload; accept a report that does not provide one.
    #[default]
    IfPresent,
    /// Reject reports that do not provide NVIDIA evidence.
    Required,
}

#[derive(Clone, Debug, Default)]
pub struct ModelAttestationPolicy {
    pub accepted_tcb_statuses: Option<Vec<TcbStatus>>,
    pub gpu_evidence: GpuEvidenceRequirement,
}

/// Gateway-specific verification policy.
#[derive(Clone, Debug)]
pub struct GatewayAttestationPolicy {
    /// Defaults to `UpToDate` and `OutOfDate` when omitted.
    pub accepted_tcb_statuses: Option<Vec<TcbStatus>>,
    /// Require the TLS peer observed by the client to match the TLS key
    /// authenticated by the Gateway quote. Defaults to `true`.
    pub verify_peer_tls_binding: bool,
}

impl Default for GatewayAttestationPolicy {
    fn default() -> Self {
        Self {
            accepted_tcb_statuses: None,
            verify_peer_tls_binding: true,
        }
    }
}

/// Optional verifier implementations used by a Gateway verification call.
#[derive(Default)]
pub struct AttestationVerifiers<'a> {
    pub quote: Option<&'a dyn QuoteVerifier>,
    pub deployment: Option<&'a dyn DeploymentVerifier>,
}

/// Optional verifier implementations used by a model verification call.
#[derive(Default)]
pub struct ModelAttestationVerifiers<'a> {
    pub quote: Option<&'a dyn QuoteVerifier>,
    pub deployment: Option<&'a dyn DeploymentVerifier>,
    pub nvidia: Option<&'a dyn NvidiaEvidenceVerifier>,
}

/// Runtime measurements reconstructed from dstack's RTMR3 event log.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeMeasurements {
    pub os_image_hash: Option<String>,
    pub compose_hash: Option<String>,
}

/// Compose configuration and runtime measurements authenticated by a quote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasuredDeployment {
    pub app_compose: String,
    pub runtime_measurements: RuntimeMeasurements,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentProvenanceStatus {
    NotChecked,
    Verified,
}

/// Measurements and signer identity established by a successful attestation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAttestationEvidence {
    pub signer: SigningIdentity,
    pub tcb_status: TcbStatus,
    pub advisory_ids: Vec<String>,
    pub deployment: MeasuredDeployment,
    pub deployment_provenance: DeploymentProvenanceStatus,
}

/// TLS information authenticated for a model report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelTlsBinding {
    None,
    /// A server-declared value, not a client-observed model TLS peer.
    Declared {
        spki_fingerprint: String,
    },
}

/// TLS information authenticated for a Gateway report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayTlsBinding {
    /// The quote authenticated the Gateway's declared TLS fingerprint.
    Attested { spki_fingerprint: String },
    /// The declared fingerprint also matched the TLS peer observed by the
    /// client for the evidence request.
    Peer { spki_fingerprint: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GpuEvidenceStatus {
    NotProvided,
    Verified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedModelAttestation {
    pub evidence: VerifiedAttestationEvidence,
    pub tls_binding: ModelTlsBinding,
    pub gpu_evidence: GpuEvidenceStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGatewayAttestation {
    pub evidence: VerifiedAttestationEvidence,
    pub tls_binding: GatewayTlsBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionSignatureKind {
    ProviderTee,
    Gateway,
}

/// The signing identity and kind required to select matching evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionSignatureReference {
    pub kind: CompletionSignatureKind,
    pub signer: SigningIdentity,
}

/// Completion signature normalized from the Cloud API wire response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionSignature {
    pub kind: CompletionSignatureKind,
    pub signed_text: String,
    pub signature: String,
    pub signer: SigningIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureUnavailable {
    pub error_code: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompletionSignatureLookup {
    Found(CompletionSignature),
    Unavailable(SignatureUnavailable),
}

/// Model evidence and the fresh nonce used to obtain it.
#[derive(Clone, Debug)]
pub struct FetchedModelAttestation {
    pub attestation: ModelAttestation,
    pub nonce: String,
}

/// Model evidence candidates and the fresh nonce used to obtain them.
#[derive(Clone, Debug)]
pub struct FetchedModelAttestations {
    pub attestations: Vec<ModelAttestation>,
    pub nonce: String,
}

/// Client values associated with a Gateway-attestation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayClientBinding {
    /// Fresh nonce sent in the Gateway-attestation request.
    pub nonce: String,
    /// SHA-256 SPKI fingerprint observed for that exact HTTPS request, when
    /// the runtime exposes peer certificate information.
    pub peer_spki_fingerprint: Option<String>,
}

/// Gateway evidence and the client values associated with its request.
#[derive(Clone, Debug)]
pub struct FetchedGatewayAttestation {
    pub attestation: GatewayAttestation,
    pub client_binding: GatewayClientBinding,
}
