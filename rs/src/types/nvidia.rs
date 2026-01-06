use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NvidiaGpuVerificationData {
    #[serde(rename = "JWT")]
    pub jwt: NvidiaJwt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NvidiaJwt {
    #[serde(rename = "x-nvidia-overall-att-result")]
    pub x_nvidia_overall_att_result: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NvidiaGpuVerificationDataRawItem {
    Jwt(String, String),
    Gpu(HashMap<String, String>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NvidiaGpuVerificationDataRaw(
    pub NvidiaGpuVerificationDataRawItem,
    pub NvidiaGpuVerificationDataRawItem,
);
