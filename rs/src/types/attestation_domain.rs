use crate::types::attestation_common::TcbInfoOrRaw;
use serde::{Deserialize, Serialize};

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
    pub tcb_info: TcbInfoOrRaw,
}
