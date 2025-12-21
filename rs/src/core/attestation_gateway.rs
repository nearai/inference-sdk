use crate::core::attestation_common::{
    get_compose_from_tcb_info, verify_compose,
    verify_intel_quote_report_data_for_attestation_report,
};
use crate::types::attestation_gateway::GatewayAttestation;
use crate::utils::consts::{ETHEREUM_ZERO_ADDRESS, TIMEOUT};
use crate::utils::errors::Error;
use crate::utils::fetch::fetch_timeout;
use crate::utils::intel::fetch_intel_tdx_verification_data;
use serde_json::Value;

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
        return Err(Error::verification("Intel quote not verified".to_owned()));
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

    let response = fetch_timeout(&url, TIMEOUT).await.map_err(Error::other)?;

    if !response.status().is_success() {
        return Err(Error::verification(format!(
            "Failed to fetch VPC info with status code {}",
            response.status()
        )));
    }

    let vpc_info: Value = response
        .json()
        .await
        .map_err(|e| Error::verification(format!("Failed to parse VPC info: {}", e)))?;

    let vpc_server_app_id_value = vpc_info
        .get("vpc_server_app_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::verification("Missing vpc_server_app_id".to_owned()))?;

    if vpc_server_app_id_value != vpc_server_app_id {
        return Err(Error::verification(
            "vpc_server_app_id mismatching".to_owned(),
        ));
    }

    let nodes = vpc_info
        .get("nodes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::verification("Missing or invalid nodes".to_owned()))?;

    let hostname_found = nodes.iter().any(|node| node.as_str() == Some(vpc_hostname));

    if !hostname_found {
        return Err(Error::verification("vpc_hostname mismatching".to_owned()));
    }

    Ok(())
}
