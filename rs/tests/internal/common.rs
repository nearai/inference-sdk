use crate::internal::types::ChatCompletionsResponse;
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use verification_sdk::{ChatSignature, DomainAttestation, GatewayAttestationReport, SigningAlgo};

pub async fn sleep(ms: u64) {
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
}

pub fn generate_request_nonce() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub async fn fetch_attestation_report(
    api_url: &str,
    api_key: &str,
    model: &str,
    request_nonce: &str,
    signing_algo: SigningAlgo,
) -> GatewayAttestationReport {
    let mut url = Url::parse(&format!("{}/attestation/report", api_url)).unwrap();

    url.query_pairs_mut()
        .append_pair("model", model)
        .append_pair("nonce", request_nonce)
        .append_pair("signing_algo", &signing_algo.to_string());

    let client = reqwest::Client::new();

    let res = client
        .get(url)
        .headers(auth_headers(api_key))
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
    api_url: &str,
    api_key: &str,
    model: &str,
    chat_id: &str,
    signing_algo: SigningAlgo,
) -> ChatSignature {
    let mut url = Url::parse(&format!("{}/signature/{}", api_url, chat_id)).unwrap();

    url.query_pairs_mut()
        .append_pair("model", model)
        .append_pair("signing_algo", &signing_algo.to_string());

    let client = reqwest::Client::new();

    let res = client
        .get(url)
        .headers(auth_headers(api_key))
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

pub async fn chat_completions(
    api_url: &str,
    api_key: &str,
    request_body: &Value,
) -> ChatCompletionsResponse {
    let request_body_raw = serde_json::to_vec(request_body).unwrap();

    let client = reqwest::Client::new();

    let res = client
        .post(format!("{}/chat/completions", api_url))
        .headers(auth_headers(api_key))
        .body(request_body_raw.clone())
        .send()
        .await
        .unwrap();

    if !res.status().is_success() {
        panic!("failed to chat with status code: {}", res.status());
    }

    let response_body_raw = res.bytes().await.unwrap().to_vec();

    #[derive(Deserialize)]
    struct WithId {
        id: String,
    }

    #[derive(Deserialize)]
    struct WithStream {
        stream: Option<bool>,
    }

    let with_stream: WithStream = serde_json::from_slice(&request_body_raw).unwrap();

    let id = if with_stream.stream.unwrap_or_default() {
        let text = String::from_utf8(response_body_raw.clone()).unwrap();
        let first_line = text.lines().next().unwrap();
        let json_part = &first_line[6..];
        let with_id: WithId = serde_json::from_str(json_part).unwrap();
        with_id.id
    } else {
        let with_id: WithId = serde_json::from_slice(&response_body_raw).unwrap();
        with_id.id
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
