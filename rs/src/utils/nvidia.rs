use crate::types::nvidia::{
    NvidiaGpuVerificationData, NvidiaGpuVerificationDataRaw, NvidiaGpuVerificationDataRawItem,
    NvidiaJwt,
};
use crate::utils::common::decode_jwt;
use crate::utils::consts::{NVIDIA_GPU_VERIFIER_API_URL, TIMEOUT};
use crate::utils::fetch::fetch_timeout_with_method;
use anyhow::Context;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use reqwest::Method;

pub async fn fetch_nvidia_gpu_verification_data(
    payload: &str,
) -> anyhow::Result<NvidiaGpuVerificationData> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let response = fetch_timeout_with_method(
        NVIDIA_GPU_VERIFIER_API_URL,
        Method::POST,
        Some(payload.to_owned()),
        Some(headers),
        TIMEOUT,
    )
    .await?;

    if !response.status().is_success() {
        anyhow::bail!(
            "failed to fetch NVIDIA GPU verification data: url={}, status={}",
            NVIDIA_GPU_VERIFIER_API_URL,
            response.status(),
        );
    }

    let verification_data_raw: NvidiaGpuVerificationDataRaw =
        response.json().await.context("failed to parse response")?;

    parse_nvidia_gpu_verification_data(&verification_data_raw)
}

fn parse_nvidia_gpu_verification_data(
    verification_data_raw: &NvidiaGpuVerificationDataRaw,
) -> anyhow::Result<NvidiaGpuVerificationData> {
    let item = &verification_data_raw.0;

    if let NvidiaGpuVerificationDataRawItem::Jwt(_, jwt) = item {
        let jwt: NvidiaJwt = decode_jwt(jwt).context("failed to decode NVIDIA JWT payload")?;
        Ok(NvidiaGpuVerificationData { jwt })
    } else {
        anyhow::bail!("invalid NVIDIA GPU verifier response format: expected first item to be JWT")
    }
}
