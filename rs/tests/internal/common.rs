use crate::internal::types::{ChatCompletionsResponse, Context};
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::Url;
use serde_json::Value;
use std::time::Duration;
use verification_sdk::{ChatSignature, DomainAttestation, GatewayAttestationReport, SigningAlgo};

pub async fn sleep(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

pub fn generate_request_nonce() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub async fn fetch_attestation_report(
    ctx: &Context,
    request_nonce: &str,
    signing_algo: SigningAlgo,
) -> GatewayAttestationReport {
    let mut url = Url::parse(&format!("{}/attestation/report", ctx.api_url)).unwrap();

    url.query_pairs_mut()
        .append_pair("model", &ctx.model)
        .append_pair("nonce", request_nonce)
        .append_pair("signing_algo", &signing_algo.to_string());

    let client = reqwest::Client::new();

    let res = client
        .get(url)
        .headers(auth_headers(&ctx.api_key))
        .send()
        .await
        .unwrap();

    if !res.status().is_success() {
        panic!(
            "failed to fetch attestation report with status code: {}",
            res.status()
        );
    }

    res.json::<GatewayAttestationReport>().await.unwrap()
}

pub async fn fetch_chat_signature(
    ctx: &Context,
    chat_id: &str,
    signing_algo: SigningAlgo,
) -> ChatSignature {
    let mut url = Url::parse(&format!("{}/signature/{}", ctx.api_url, chat_id)).unwrap();

    url.query_pairs_mut()
        .append_pair("model", &ctx.model)
        .append_pair("signing_algo", &signing_algo.to_string());

    let client = reqwest::Client::new();

    let res = client
        .get(url)
        .headers(auth_headers(&ctx.api_key))
        .send()
        .await
        .unwrap();

    if !res.status().is_success() {
        panic!(
            "failed to fetch chat signature with status code: {}",
            res.status()
        );
    }

    res.json::<ChatSignature>().await.unwrap()
}

pub async fn chat_completions(ctx: &Context, request_body: &Value) -> ChatCompletionsResponse {
    let request_body_raw = serde_json::to_vec(request_body).unwrap();

    let client = reqwest::Client::new();

    let res = client
        .post(format!("{}/chat/completions", ctx.api_url))
        .headers(auth_headers(&ctx.api_key))
        .body(request_body_raw.clone())
        .send()
        .await
        .unwrap();

    if !res.status().is_success() {
        panic!("failed to chat with status code: {}", res.status());
    }

    let response_body_raw = res.bytes().await.unwrap().to_vec();

    let id = if request_body
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        // stream response: first line is "data: {...}"
        let text = String::from_utf8_lossy(&response_body_raw);
        let first_line = text.lines().next().unwrap_or("");
        let json_part = first_line
            .strip_prefix("data: ")
            .unwrap_or(first_line)
            .trim();
        let v: Value = serde_json::from_str(json_part).expect("invalid stream chunk json");
        v.get("id")
            .and_then(|v| v.as_str())
            .expect("missing id")
            .to_owned()
    } else {
        let v: Value = serde_json::from_slice(&response_body_raw).expect("invalid json");
        v.get("id")
            .and_then(|v| v.as_str())
            .expect("missing id")
            .to_owned()
    };

    ChatCompletionsResponse {
        id,
        request_body_raw,
        response_body_raw,
    }
}

pub async fn fetch_domain_attestation(domain: &str) -> DomainAttestation {
    let evidences_url = format!("https://{}/evidences/", domain);

    let intel_quote_url = format!("{}quote.json", evidences_url);
    let cert_url = format!("{}cert-{}.pem", evidences_url, domain);
    let acme_account_url = format!("{}acme-account.json", evidences_url);
    let sha256sum_url = format!("{}sha256sum.txt", evidences_url);
    let info_url = format!("{}info.json", evidences_url);

    let client = reqwest::Client::new();

    let (intel_quote_res, cert_res, acme_account_res, sha256sum_res, info_res) = tokio::join!(
        client.get(intel_quote_url).send(),
        client.get(cert_url).send(),
        client.get(acme_account_url).send(),
        client.get(sha256sum_url).send(),
        client.get(info_url).send(),
    );

    let intel_quote_res = intel_quote_res.unwrap();
    let cert_res = cert_res.unwrap();
    let acme_account_res = acme_account_res.unwrap();
    let sha256sum_res = sha256sum_res.unwrap();
    let info_res = info_res.unwrap();

    if !intel_quote_res.status().is_success() {
        panic!(
            "failed to fetch Intel quote with status code: {}",
            intel_quote_res.status()
        );
    }

    if !cert_res.status().is_success() {
        panic!(
            "failed to fetch certificate with status code: {}",
            cert_res.status()
        );
    }

    if !acme_account_res.status().is_success() {
        panic!(
            "failed to fetch ACME account with status code: {}",
            acme_account_res.status()
        );
    }

    if !sha256sum_res.status().is_success() {
        panic!(
            "failed to fetch sha256 sum with status code: {}",
            sha256sum_res.status()
        );
    }

    if !info_res.status().is_success() {
        panic!(
            "failed to fetch info with status code: {}",
            info_res.status()
        );
    }

    let intel_quote_json: Value = intel_quote_res.json().await.unwrap();

    let intel_quote = intel_quote_json["quote"].as_str().unwrap().to_owned();

    let cert = cert_res.text().await.unwrap();

    let acme_account = acme_account_res.text().await.unwrap();

    let sha256sum = sha256sum_res.text().await.unwrap();

    DomainAttestation {
        intel_quote,
        domain: domain.to_owned(),
        cert,
        acme_account,
        sha256sum,
        info: info_res.json().await.unwrap(),
    }
}

fn auth_headers(api_key: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", api_key)).unwrap(),
    );
    headers
}
