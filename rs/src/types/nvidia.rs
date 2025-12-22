use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NvidiaGpuVerificationDataRaw(pub (String, String));

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
