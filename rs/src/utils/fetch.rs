use crate::utils::errors::VerificationError;
use reqwest::Client;
use std::time::Duration;

pub async fn fetch_timeout(
    url: &str,
    timeout_ms: u64,
) -> Result<reqwest::Response, VerificationError> {
    let client = Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .map_err(|e| VerificationError::new(format!("Failed to create HTTP client: {}", e)))?;

    client
        .get(url)
        .send()
        .await
        .map_err(|e| VerificationError::new(format!("Fetch url {} error: {}", url, e)))
}

pub async fn fetch_timeout_with_method(
    url: &str,
    timeout_ms: u64,
    method: reqwest::Method,
    body: Option<String>,
) -> Result<reqwest::Response, VerificationError> {
    let client = Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .map_err(|e| VerificationError::new(format!("Failed to create HTTP client: {}", e)))?;

    let mut request = client.request(method, url);

    if let Some(body_str) = body {
        request = request
            .header("content-type", "application/json")
            .body(body_str);
    }

    request
        .send()
        .await
        .map_err(|e| VerificationError::new(format!("Fetch url {} error: {}", url, e)))
}

