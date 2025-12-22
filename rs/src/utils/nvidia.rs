use crate::types::nvidia::{
    NvidiaGpuVerificationData, NvidiaGpuVerificationDataRaw, NvidiaGpuVerificationDataRawItem,
    NvidiaJwt,
};
use crate::utils::common::decode_jwt;
use crate::utils::consts::{NVIDIA_GPU_VERIFIER_API_URL, TIMEOUT};
use crate::utils::errors::Error;
use crate::utils::fetch::fetch_timeout_with_method;
use anyhow::Context;
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
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read response body>".to_owned());
        return Err(Error::common(format!(
            "failed to fetch NVIDIA GPU verification data: url={}, status={}, body={}",
            NVIDIA_GPU_VERIFIER_API_URL, status, body
        )));
    }

    let verification_data_raw: NvidiaGpuVerificationDataRaw =
        response.json().await.context("failed to parse response")?;

    parse_nvidia_gpu_verification_data(&verification_data_raw)
}

fn parse_nvidia_gpu_verification_data(
    verification_data_raw: &NvidiaGpuVerificationDataRaw,
) -> Result<NvidiaGpuVerificationData, Error> {
    let item = &verification_data_raw.0;

    if let NvidiaGpuVerificationDataRawItem::Jwt(_, jwt) = item {
        let jwt: NvidiaJwt = decode_jwt(jwt).context("failed to decode NVIDIA JWT payload")?;
        Ok(NvidiaGpuVerificationData { jwt })
    } else {
        Err(Error::common(
            "invalid NVIDIA GPU verifier response format: expected first item to be JWT".to_owned(),
        ))
    }
}
