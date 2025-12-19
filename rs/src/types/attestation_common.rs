use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningAlgo {
    Ecdsa,
    #[serde(rename = "ed25519")]
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcbInfo {
    pub app_compose: String,
}

