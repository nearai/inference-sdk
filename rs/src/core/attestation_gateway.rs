use crate::core::attestation_common::{
    get_compose_from_tcb_info, verify_compose,
    verify_intel_quote_report_data_for_attestation_report,
};
use crate::types::attestation_gateway::GatewayAttestation;
use crate::utils::consts::{ETHEREUM_ZERO_ADDRESS, TIMEOUT};
use crate::utils::errors::Error;
use crate::utils::fetch::fetch_timeout;
use crate::utils::intel::fetch_intel_tdx_verification_data;
use anyhow::Context;
use serde::Deserialize;

pub async fn verify_gateway_attestation(
    attestation: &GatewayAttestation,
    domain: &str,
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
        domain,
        &attestation.vpc.vpc_server_app_id,
        &attestation.vpc.vpc_hostname,
    )
    .await?;

    let compose = get_compose_from_tcb_info(&attestation.info.tcb_info)?;
    verify_compose(&compose).await?;

    Ok(())
}

fn verify_intel_tdx_for_gateway(
    verification_data: &crate::types::intel::IntelTdxVerificationData,
    request_nonce: &str,
    signing_address: &str,
) -> Result<(), Error> {
    if !verification_data.quote.verified {
        return Err(Error::verification(
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

    let response = fetch_timeout(&url, TIMEOUT).await?;

    if !response.status().is_success() {
        return Err(Error::other(format!(
            "failed to fetch VPC info: url={}, status={}",
            url,
            response.status(),
        )));
    }

    #[derive(Deserialize)]
    struct VpcInfo {
        vpc_server_app_id: String,
        nodes: Vec<String>,
    }

    let vpc_info: VpcInfo = response.json().await.context("failed to parse VPC info")?;

    if vpc_server_app_id != vpc_info.vpc_server_app_id {
        return Err(Error::verification(format!(
            "vpc_server_app_id mismatching: expected '{}', got '{}'",
            vpc_info.vpc_server_app_id, vpc_server_app_id
        )));
    }

    let hostname_found = vpc_info.nodes.iter().any(|node| node == vpc_hostname);

    if !hostname_found {
        return Err(Error::verification(format!(
            "vpc_hostname mismatching: expected '{}' to be present in nodes",
            vpc_hostname
        )));
    }

    Ok(())
}
