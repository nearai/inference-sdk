use serde::{Deserialize, Serialize};
use crate::types::attestation_common::SigningAlgo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chat {
    #[serde(with = "serde_bytes")]
    pub request_body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub response_body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSignature {
    pub text: String,
    pub signature: String,
    pub signing_address: String,
    pub signing_algo: SigningAlgo,
}

