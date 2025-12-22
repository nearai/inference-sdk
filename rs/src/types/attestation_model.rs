use crate::types::attestation_common::{SigningAlgo, TcbInfoOrRaw};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelAttestation {
    pub request_nonce: String,
    pub signing_algo: SigningAlgo,
    pub signing_address: String,
    pub intel_quote: String,
    pub nvidia_payload: String,
    pub info: ModelAttestationInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelAttestationInfo {
    pub tcb_info: TcbInfoOrRaw,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelAttestationReport {
    pub all_attestations: Vec<ModelAttestation>,
}
