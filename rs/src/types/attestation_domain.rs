use serde::{Deserialize, Serialize};
use crate::types::attestation_common::TcbInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainAttestation {
    pub intel_quote: String,
    pub domain: String,
    pub cert: String,
    pub acme_account: String,
    pub sha256sum: String,
    pub info: DomainAttestationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainAttestationInfo {
    #[serde(flatten)]
    pub tcb_info: TcbInfoOrString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TcbInfoOrString {
    String(String),
    Object(TcbInfo),
}

