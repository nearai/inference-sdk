use crate::core::attestation_common::{
    get_compose_from_tcb_info, verify_compose,
    verify_intel_quote_report_data_for_attestation_report,
};
use crate::types::attestation_gateway::{GatewayAttestation, VerifyGatewayAttestationConfig};
use crate::utils::consts::{ETHEREUM_ZERO_ADDRESS, TIMEOUT};
use crate::utils::errors::Error;
use crate::utils::intel::fetch_intel_tdx_verification_data;
use anyhow::Context;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

pub async fn verify_gateway_attestation(
    attestation: &GatewayAttestation,
    config: &VerifyGatewayAttestationConfig,
) -> Result<(), Error> {
    let verification_data = fetch_intel_tdx_verification_data(&attestation.intel_quote).await?;

    verify_intel_tdx_for_gateway(
        &verification_data,
        &attestation.request_nonce,
        attestation
            .signing_address
            .as_deref()
            .unwrap_or(ETHEREUM_ZERO_ADDRESS),
    )?;

    verify_vpc_for_gateway(
        &config.domain,
        &attestation.vpc.vpc_server_app_id,
        &attestation.vpc.vpc_hostname,
    )
    .await?;

    if !config.image_names_of_sigstore_hash.is_empty() {
        let compose = get_compose_from_tcb_info(&attestation.info.tcb_info)?;
        verify_compose(&compose, &config.image_names_of_sigstore_hash).await?;
    }

    Ok(())
}

fn verify_intel_tdx_for_gateway(
    verification_data: &crate::types::intel::IntelTdxVerificationData,
    request_nonce: &str,
    signing_address: &str,
) -> Result<(), Error> {
    if !verification_data.quote.verified {
        return Err(Error::VerificationError(
            "Intel quote not verified: quote.verified=false".to_owned(),
        ));
    }

    verify_intel_quote_report_data_for_attestation_report(
        &verification_data.quote.body.reportdata,
        request_nonce,
        signing_address,
    )
}

async fn verify_vpc_for_gateway(
    domain: &str,
    vpc_server_app_id: &str,
    vpc_hostname: &str,
) -> Result<(), Error> {
    let url = format!("https://{}/evidences/vpc.json", domain);

    let client = Client::builder()
        .timeout(Duration::from_millis(TIMEOUT))
        .build()
        .context("failed to build http client")?;

    let response = client
        .get(&url)
        .send()
        .await
        .context("failed to send request")?;

    if !response.status().is_success() {
        let msg = format!(
            "failed to fetch VPC info: url={}, status={}",
            url,
            response.status(),
        );
        return Err(anyhow::Error::msg(msg).into());
    }

    #[derive(Deserialize)]
    struct VpcInfo {
        vpc_server_app_id: String,
        nodes: Vec<String>,
    }

    let vpc_info: VpcInfo = response.json().await.context("failed to parse VPC info")?;

    if vpc_server_app_id != vpc_info.vpc_server_app_id {
        return Err(Error::VerificationError(format!(
            "vpc_server_app_id mismatching: expected '{}', got '{}'",
            vpc_info.vpc_server_app_id, vpc_server_app_id
        )));
    }

    let hostname_found = vpc_info.nodes.iter().any(|node| node == vpc_hostname);

    if !hostname_found {
        return Err(Error::VerificationError(format!(
            "vpc_hostname mismatching: expected '{}' to be present in nodes",
            vpc_hostname
        )));
    }

    Ok(())
}
