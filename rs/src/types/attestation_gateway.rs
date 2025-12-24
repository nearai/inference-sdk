use crate::types::attestation_common::{SigningAlgo, TcbInfoOrRaw};
use crate::types::attestation_model::ModelAttestation;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayAttestationInfo {
    pub tcb_info: TcbInfoOrRaw,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayVpc {
    pub vpc_server_app_id: String,
    pub vpc_hostname: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayAttestationReport {
    pub gateway_attestation: GatewayAttestation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_attestations: Option<Vec<ModelAttestation>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyGatewayAttestationConfig {
    pub domain: String,
    pub image_names_of_sigstore_hash: Vec<String>,
}
