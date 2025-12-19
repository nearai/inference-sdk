use serde::{Deserialize, Serialize};
use crate::types::attestation_common::{SigningAlgo, TcbInfo};
use crate::types::attestation_model::ModelAttestation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayAttestation {
    pub request_nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_algo: Option<SigningAlgo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_address: Option<String>,
    pub intel_quote: String,
    pub info: GatewayAttestationInfo,
    pub vpc: GatewayVpc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayAttestationInfo {
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
pub struct GatewayVpc {
    pub vpc_server_app_id: String,
    pub vpc_hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayAttestationReport {
    pub gateway_attestation: GatewayAttestation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_attestations: Option<Vec<ModelAttestation>>,
}

