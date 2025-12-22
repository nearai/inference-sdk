use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NvidiaGpuVerificationData {
    #[serde(rename = "JWT")]
    pub jwt: HashMap<String, serde_json::Value>,
    #[serde(rename = "GPU")]
    pub gpu: HashMap<String, HashMap<String, serde_json::Value>>,
}
