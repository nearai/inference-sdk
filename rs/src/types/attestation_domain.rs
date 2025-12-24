use crate::types::attestation_common::TcbInfoOrRaw;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainAttestation {
    pub intel_quote: String,
    pub domain: String,
    pub cert: String,
    pub acme_account: String,
    pub sha256sum: String,
    pub info: DomainAttestationInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainAttestationInfo {
    pub tcb_info: TcbInfoOrRaw,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyDomainAttestationConfig {
    pub image_names_of_sigstore_hash: Vec<String>,
}
