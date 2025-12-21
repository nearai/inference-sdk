use crate::types::attestation_common::{SigningAlgo, TcbInfoOrRaw};
use crate::types::attestation_model::ModelAttestation;
use serde::{Deserialize, Serialize};

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
    pub tcb_info: TcbInfoOrRaw,
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
