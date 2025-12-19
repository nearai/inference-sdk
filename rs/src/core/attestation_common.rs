use crate::types::attestation_common::TcbInfo;
use crate::utils::common::hex_to_bytes;
use crate::utils::consts::{SIGSTORE_SEARCH_API_URL, TIMEOUT};
use crate::utils::errors::VerificationError;
use crate::utils::fetch::fetch_timeout;
use regex::Regex;
use reqwest::Method;
use serde_json::Value;

pub fn verify_intel_quote_report_data_for_attestation_report(
    report_data: &str,
    request_nonce: &str,
    signing_address: &str,
) -> Result<(), VerificationError> {
    let report_raw = hex_to_bytes(report_data)?;
    let signing_address_raw = hex_to_bytes(signing_address)?;

    if report_raw.len() < 32 {
        return Err(VerificationError::new("Invalid report data length".to_string()));
    }

    let embedded_address = &report_raw[0..32];
    let embedded_nonce = &report_raw[32..];

    let mut padded_address = signing_address_raw.clone();
    padded_address.resize(32, 0);

    if embedded_address != padded_address.as_slice() {
        return Err(VerificationError::new("Signing address mismatching".to_string()));
    }

    let request_nonce_bytes = hex_to_bytes(request_nonce)?;
    if embedded_nonce != request_nonce_bytes.as_slice() {
        return Err(VerificationError::new("Request nonce mismatching".to_string()));
    }

    Ok(())
}

pub fn get_compose_from_tcb_info(tcb_info: &Value) -> Result<String, VerificationError> {
    let tcb_info_obj = if let Value::String(s) = tcb_info {
        serde_json::from_str::<TcbInfo>(s)
            .map_err(|_| VerificationError::new("Invalid tcb info".to_string()))?
    } else {
        serde_json::from_value::<TcbInfo>(tcb_info.clone())
            .map_err(|_| VerificationError::new("Invalid tcb info".to_string()))?
    };

    Ok(tcb_info_obj.app_compose)
}

pub async fn verify_compose(compose: &str) -> Result<(), VerificationError> {
    let links = get_sigstore_links_from_compose(compose)?;

    for link in links {
        verify_sigstore_link(&link).await?;
    }

    Ok(())
}

fn get_sigstore_links_from_compose(compose: &str) -> Result<Vec<String>, VerificationError> {
    let re = Regex::new(r"@sha256:([0-9a-f]{64})")
        .map_err(|e| VerificationError::new(format!("Failed to create regex: {}", e)))?;

    let mut digests = std::collections::HashSet::new();

    for cap in re.captures_iter(compose) {
        if let Some(digest) = cap.get(1) {
            digests.insert(digest.as_str().to_string());
        }
    }

    if digests.is_empty() {
        return Err(VerificationError::new(
            "Failed to get sigstore links from compose".to_string(),
        ));
    }

    Ok(digests
        .iter()
        .map(|digest| format!("{}/?hash=sha256:{}", SIGSTORE_SEARCH_API_URL, digest))
        .collect())
}

async fn verify_sigstore_link(link: &str) -> Result<(), VerificationError> {
    let response = crate::utils::fetch::fetch_timeout_with_method(
        link,
        TIMEOUT,
        Method::HEAD,
        None,
    )
    .await?;

    if !response.status().is_success() {
        return Err(VerificationError::new(format!(
            "Failed to verify sigstore link {} with status code {}",
            link,
            response.status()
        )));
    }

    Ok(())
}

