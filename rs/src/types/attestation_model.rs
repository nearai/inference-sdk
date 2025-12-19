use serde::{Deserialize, Serialize};
use crate::types::attestation_common::{SigningAlgo, TcbInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAttestation {
    pub request_nonce: String,
    pub signing_algo: SigningAlgo,
    pub signing_address: String,
    pub intel_quote: String,
    pub nvidia_payload: String,
    pub info: ModelAttestationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAttestationInfo {
    #[serde(flatten)]
    pub tcb_info: TcbInfoOrString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TcbInfoOrString {
    String(String),
    Object(TcbInfo),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAttestationReport {
    pub all_attestations: Vec<ModelAttestation>,
}

