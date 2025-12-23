use crate::types::attestation_common::{TcbInfo, TcbInfoOrRaw};
use crate::utils::common::hex_to_bytes;
use crate::utils::consts::{SIGSTORE_SEARCH_API_URL, TIMEOUT};
use crate::utils::errors::Error;
use crate::utils::fetch::fetch_timeout_with_method;
use anyhow::Context;
use regex::Regex;
use reqwest::Method;

pub fn verify_intel_quote_report_data_for_attestation_report(
    report_data: &str,
    request_nonce: &str,
    signing_address: &str,
) -> Result<(), Error> {
    let report_data_raw = hex_to_bytes(report_data)?;
    let signing_address_raw = hex_to_bytes(signing_address)?;

    if report_data_raw.len() < 32 {
        return Err(Error::VerificationError(
            "invalid report data length".to_owned(),
        ));
    }

    let embedded_address = &report_data_raw[0..32];
    let embedded_nonce = &report_data_raw[32..];

    let mut padded_address = signing_address_raw.clone();
    padded_address.resize(32, 0);

    if embedded_address != padded_address.as_slice() {
        return Err(Error::VerificationError(
            "signing address mismatching".to_owned(),
        ));
    }

    let request_nonce_raw = hex_to_bytes(request_nonce)?;

    if embedded_nonce != request_nonce_raw.as_slice() {
        return Err(Error::VerificationError(
            "request nonce mismatching".to_owned(),
        ));
    }

    Ok(())
}

pub fn get_compose_from_tcb_info(tcb_info: &TcbInfoOrRaw) -> Result<String, Error> {
    let tcb_info = TcbInfo::try_from(tcb_info.to_owned())
        .map_err(|e| Error::VerificationError(format!("invalid tcb info: {}", e)))?;

    Ok(tcb_info.app_compose)
}

pub async fn verify_compose(compose: &str) -> Result<(), Error> {
    let links = get_sigstore_links_from_compose(compose)?;

    for link in links {
        verify_sigstore_link(&link).await?;
    }

    Ok(())
}

fn get_sigstore_links_from_compose(compose: &str) -> Result<Vec<String>, Error> {
    let re = Regex::new(r"@sha256:([0-9a-f]{64})").context("failed to create regex")?;

    let mut digests = std::collections::HashSet::new();

    for cap in re.captures_iter(compose) {
        if let Some(digest) = cap.get(1) {
            digests.insert(digest.as_str().to_owned());
        }
    }

    if digests.is_empty() {
        return Err(Error::VerificationError(
            "failed to get sigstore links from compose".to_owned(),
        ));
    }

    Ok(digests
        .iter()
        .map(|digest| format!("{}/?hash=sha256:{}", SIGSTORE_SEARCH_API_URL, digest))
        .collect())
}

async fn verify_sigstore_link(link: &str) -> Result<(), Error> {
    let response = fetch_timeout_with_method(link, TIMEOUT, Method::HEAD, None).await?;

    if !response.status().is_success() {
        return Err(Error::VerificationError(format!(
            "failed to verify sigstore link {} with status code {}",
            link,
            response.status()
        )));
    }

    Ok(())
}
