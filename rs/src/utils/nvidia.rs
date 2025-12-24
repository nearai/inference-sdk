use crate::types::nvidia::{
    NvidiaGpuVerificationData, NvidiaGpuVerificationDataRaw, NvidiaGpuVerificationDataRawItem,
    NvidiaJwt,
};
use crate::utils::common::decode_jwt;
use crate::utils::consts::{NVIDIA_GPU_VERIFIER_API_URL, SIGSTORE_SEARCH_API_URL, TIMEOUT};
use anyhow::Context;
use reqwest::header::CONTENT_TYPE;
use reqwest::Client;
use std::time::Duration;

pub async fn fetch_nvidia_gpu_verification_data(
    payload: &str,
) -> anyhow::Result<NvidiaGpuVerificationData> {
    let client = Client::builder()
        .timeout(Duration::from_millis(TIMEOUT))
        .build()
        .context("failed to build http client")?;

    let response = client
        .post(SIGSTORE_SEARCH_API_URL)
        .header(CONTENT_TYPE, "application/json")
        .body(payload.to_owned())
        .send()
        .await
        .context("failed to send request")?;

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
