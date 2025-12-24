use crate::types::attestation_common::{TcbInfo, TcbInfoOrRaw};
use crate::utils::common::hex_to_bytes;
use crate::utils::consts::{SIGSTORE_SEARCH_API_URL, TIMEOUT};
use crate::utils::errors::Error;
use crate::utils::fetch::fetch_timeout_with_method;
use anyhow::Context;
use regex::Regex;
use reqwest::header::{HeaderMap, CONTENT_TYPE};
use reqwest::Method;
use serde::Serialize;
use std::collections::HashSet;

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

pub async fn verify_compose(
    compose: &str,
    image_names_of_sigstore_hash: &[String],
) -> Result<(), Error> {
    let hashes = get_sigstore_hashes_from_compose(compose, image_names_of_sigstore_hash)?;

    for hash in hashes {
        verify_sigstore_hash(&hash).await?;
    }

    Ok(())
}

fn get_sigstore_hashes_from_compose(
    compose: &str,
    image_names_of_sigstore_hash: &[String],
) -> Result<Vec<String>, Error> {
    let names: HashSet<&str> = image_names_of_sigstore_hash
        .iter()
        .map(|s| s.as_str())
        .collect();

    let mut found_names: HashSet<&str> = HashSet::new();
    let mut found_digests: Vec<String> = Vec::new();

    // Match "<image-name>@sha256:<64-hex-digest>"
    let re = Regex::new(r"([^@\s]+)@sha256:([0-9a-f]{64})").context("failed to create regex")?;

    for cap in re.captures_iter(compose) {
        let name = cap.get(1).map(|m| m.as_str());
        let digest = cap.get(2).map(|m| m.as_str());

        let (Some(name), Some(digest)) = (name, digest) else {
            continue;
        };

        if !names.contains(name) {
            continue;
        }

        found_names.insert(name);
        found_digests.push(digest.to_owned());
    }

    let missing_names: Vec<&str> = image_names_of_sigstore_hash
        .iter()
        .map(String::as_str)
        .filter(|&n| !found_names.contains(n))
        .collect();

    if !missing_names.is_empty() {
        return Err(Error::VerificationError(format!(
            "missing sigstore hash for image: {}",
            missing_names.join(", ")
        )));
    }

    Ok(found_digests)
}

async fn verify_sigstore_hash(hash: &str) -> Result<(), Error> {
    #[derive(Serialize)]
    struct Body<'a> {
        hash: &'a str,
    }

    let body = serde_json::to_vec(&Body { hash }).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

    let response = fetch_timeout_with_method(
        SIGSTORE_SEARCH_API_URL,
        TIMEOUT,
        Method::POST,
        Some(body),
        Some(headers),
    )
    .await?;

    if !response.status().is_success() {
        return Err(Error::VerificationError(format!(
            "failed to verify sigstore hash with status code {}",
            response.status()
        )));
    }

    let outputs: Vec<String> = response
        .json()
        .await
        .context("failed to parse sigstore outputs")?;

    if outputs.is_empty() {
        return Err(Error::VerificationError(format!(
            "invalid sigstore hash {}",
            hash
        )));
    }

    Ok(())
}
