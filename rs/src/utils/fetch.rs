use reqwest::header::HeaderMap;
use reqwest::{Body, Client, Method, Response};
use std::time::Duration;

pub async fn fetch_timeout(url: &str, timeout_ms: u64) -> anyhow::Result<Response> {
    let client = Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()?;

    Ok(client.get(url).send().await?)
}

pub async fn fetch_timeout_with_method<T: Into<Body>>(
    url: &str,
    method: Method,
    body: Option<T>,
    headers: Option<HeaderMap>,
    timeout_ms: u64,
) -> anyhow::Result<Response> {
    let client = Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()?;

    let mut request = client.request(method, url);

    if let Some(body) = body {
        request = request.body(body);
    }

    if let Some(header) = headers {
        request = request.headers(header)
    }

    Ok(request.send().await?)
}
