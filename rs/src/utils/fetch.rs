use reqwest::{Client, Method, Response};
use std::time::Duration;

pub async fn fetch_timeout(url: &str, timeout_ms: u64) -> anyhow::Result<Response> {
    let client = Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()?;

    Ok(client.get(url).send().await?)
}

pub async fn fetch_timeout_with_method(
    url: &str,
    timeout_ms: u64,
    method: Method,
    body: Option<String>,
) -> anyhow::Result<Response> {
    let client = Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()?;

    let mut request = client.request(method, url);

    if let Some(body_str) = body {
        request = request
            .header("content-type", "application/json")
            .body(body_str);
    }

    Ok(request.send().await?)
}
