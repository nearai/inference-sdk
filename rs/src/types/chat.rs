use crate::types::attestation_common::SigningAlgo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Chat {
    pub request_body: Vec<u8>,
    pub response_body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSignature {
    pub text: String,
    pub signature: String,
    pub signing_address: String,
    pub signing_algo: SigningAlgo,
}
