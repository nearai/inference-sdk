use crate::types::nvidia::NvidiaGpuVerificationData;
use crate::utils::common::decode_jwt;
use crate::utils::consts::{NVIDIA_GPU_VERIFIER_API_URL, TIMEOUT};
use crate::utils::errors::VerificationError;
use crate::utils::fetch::fetch_timeout_with_method;
use reqwest::Method;
use serde_json::Value;
use std::collections::HashMap;

pub async fn fetch_nvidia_gpu_verification_data(
    payload: &str,
) -> Result<NvidiaGpuVerificationData, VerificationError> {
    let response = fetch_timeout_with_method(
        NVIDIA_GPU_VERIFIER_API_URL,
        TIMEOUT,
        Method::POST,
        Some(payload.to_string()),
    )
    .await?;

    if !response.status().is_success() {
        return Err(VerificationError::new(format!(
            "Failed to fetch NVIDIA GPU verification data with status code {}",
            response.status()
        )));
    }

    let verification_data_raw: Value = response
        .json()
        .await
        .map_err(|e| VerificationError::new(format!("Failed to parse response: {}", e)))?;

    parse_nvidia_gpu_verification_data(&verification_data_raw)
}

fn parse_nvidia_gpu_verification_data(
    verification_data_raw: &Value,
) -> Result<NvidiaGpuVerificationData, VerificationError> {
    let array = verification_data_raw
        .as_array()
        .ok_or_else(|| VerificationError::new("Invalid response format".to_string()))?;

    if array.len() < 2 {
        return Err(VerificationError::new("Invalid response format".to_string()));
    }

    let jwt_array = array[0]
        .as_array()
        .ok_or_else(|| VerificationError::new("Invalid JWT format".to_string()))?;

    if jwt_array.len() < 2 || jwt_array[0].as_str() != Some("JWT") {
        return Err(VerificationError::new("Invalid JWT format".to_string()));
    }

    let jwt_str = jwt_array[1]
        .as_str()
        .ok_or_else(|| VerificationError::new("Invalid JWT format".to_string()))?;

    let jwt = decode_jwt(jwt_str)?;

    let gpu_obj = array[1]
        .as_object()
        .ok_or_else(|| VerificationError::new("Invalid GPU format".to_string()))?;

    let mut gpu: HashMap<String, HashMap<String, Value>> = HashMap::new();

    for (key, value) in gpu_obj {
        let value_str = value
            .as_str()
            .ok_or_else(|| VerificationError::new("Invalid GPU JWT format".to_string()))?;
        let decoded = decode_jwt(value_str)?;
        gpu.insert(key.clone(), decoded);
    }

    Ok(NvidiaGpuVerificationData { jwt, gpu })
}

