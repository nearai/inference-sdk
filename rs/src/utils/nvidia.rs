use crate::types::nvidia::{NvidiaGpuVerificationData, NvidiaGpuVerificationDataRaw, NvidiaJwt};
use crate::utils::common::decode_jwt;
use crate::utils::consts::{NVIDIA_GPU_VERIFIER_API_URL, TIMEOUT};
use crate::utils::errors::Error;
use crate::utils::fetch::fetch_timeout_with_method;
use reqwest::Method;

pub async fn fetch_nvidia_gpu_verification_data(
    payload: &str,
) -> Result<NvidiaGpuVerificationData, Error> {
    let response = fetch_timeout_with_method(
        NVIDIA_GPU_VERIFIER_API_URL,
        TIMEOUT,
        Method::POST,
        Some(payload.to_owned()),
    )
    .await
    .map_err(Error::other)?;

    if !response.status().is_success() {
        return Err(Error::verification(format!(
            "failed to fetch NVIDIA GPU verification data with status code {}",
            response.status()
        )));
    }

    let verification_data_raw: NvidiaGpuVerificationDataRaw = response
        .json()
        .await
        .map_err(|e| Error::verification(format!("failed to parse response: {}", e)))?;

    parse_nvidia_gpu_verification_data(&verification_data_raw)
}

fn parse_nvidia_gpu_verification_data(
    verification_data_raw: &NvidiaGpuVerificationDataRaw,
) -> Result<NvidiaGpuVerificationData, Error> {
    let jwt_entry = &verification_data_raw.0;

    if jwt_entry.0 != "JWT" {
        return Err(Error::verification("invalid JWT format".to_owned()));
    }

    let jwt: NvidiaJwt = decode_jwt(&jwt_entry.1)?;

    Ok(NvidiaGpuVerificationData { jwt })
}
