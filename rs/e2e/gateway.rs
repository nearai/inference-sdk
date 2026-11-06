mod integrated;
mod messages;
mod responses;
mod systemone;

use std::{env, error::Error, io, time::Duration};

use nearai_inference_sdk::{
    create_pinned_tls_client, find_model_attestations_for_signature, verify_gateway_attestation,
    verify_gateway_response, verify_model_attestation, verify_model_response, ApiError,
    AttestationClient, CompletionSignature, CompletionSignatureKind,
    GatewayAttestationFetchOptions, GatewayTlsBinding, GpuEvidenceStatus, SigningAlgo,
    SigningIdentity,
};
use reqwest::header::{ACCEPT_ENCODING, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::{json, Value};

#[tokio::test]
#[ignore = "requires NEARAI_BASE_URL, NEARAI_API_KEY and NEARAI_E2E_MODELS"]
async fn ed25519_gateway_chat_receipts() -> Result<(), Box<dyn Error>> {
    verify_models(SigningAlgo::Ed25519).await
}

#[tokio::test]
#[ignore = "requires NEARAI_BASE_URL, NEARAI_API_KEY and NEARAI_E2E_MODELS"]
async fn ecdsa_gateway_chat_receipts() -> Result<(), Box<dyn Error>> {
    verify_models(SigningAlgo::Ecdsa).await
}

#[derive(Deserialize)]
struct LiveModel {
    id: String,
    provider: String,
    endpoint: String,
}

fn same_signer(left: &SigningIdentity, right: &SigningIdentity) -> bool {
    left.signing_algo == right.signing_algo
        && left
            .signing_address
            .to_ascii_lowercase()
            .trim_start_matches("0x")
            == right
                .signing_address
                .to_ascii_lowercase()
                .trim_start_matches("0x")
}

fn select_models(json: &str, endpoint: &str) -> Result<Vec<LiveModel>, serde_json::Error> {
    let models: Vec<LiveModel> = serde_json::from_str(json)?;
    let models: Vec<_> = models
        .into_iter()
        .filter(|model| model.endpoint == endpoint)
        .collect();
    assert!(
        !models.is_empty(),
        "Expected representative {endpoint} models"
    );
    Ok(models)
}

#[test]
fn selects_models_by_endpoint() {
    let json = r#"[
        {"id":"near/chat","provider":"near","endpoint":"chat"},
        {"id":"typesafe/decision","provider":"external","endpoint":"systemone"},
        {"id":"anthropic/text","provider":"external","endpoint":"messages"}
    ]"#;
    for (endpoint, id) in [
        ("chat", "near/chat"),
        ("systemone", "typesafe/decision"),
        ("messages", "anthropic/text"),
    ] {
        let models = select_models(json, endpoint).unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, id);
    }
}

async fn verify_models(signing_algo: SigningAlgo) -> Result<(), Box<dyn Error>> {
    let models = select_models(&required_env("NEARAI_E2E_MODELS")?, "chat")?;
    for model in &models {
        println!("{}: {}, {signing_algo}", model.provider, model.id);
        tokio::time::timeout(Duration::from_secs(180), verify_chat(signing_algo, model)).await??;
    }
    Ok(())
}

async fn verify_chat(signing_algo: SigningAlgo, model: &LiveModel) -> Result<(), Box<dyn Error>> {
    let base_url = required_env("NEARAI_BASE_URL")?;
    let api_key = required_env("NEARAI_API_KEY")?;
    let client = AttestationClient::with_base_url(api_key.clone(), &base_url)?;

    let fetched_gateway = client
        .fetch_gateway_attestation(GatewayAttestationFetchOptions {
            signing_algo: Some(signing_algo),
            ..Default::default()
        })
        .await?;
    let gateway = verify_gateway_attestation(
        &fetched_gateway.attestation,
        &fetched_gateway.client_binding,
        None,
        Default::default(),
    )
    .await?;
    assert!(matches!(
        gateway.tls_binding,
        GatewayTlsBinding::Attested { .. }
    ));

    // Pin all subsequent evidence, Chat, and signature requests to the verified Gateway.
    let pin = match &gateway.tls_binding {
        GatewayTlsBinding::Attested { spki_fingerprint } => spki_fingerprint,
        GatewayTlsBinding::None => {
            return Err(io::Error::other("Missing Gateway TLS binding").into())
        }
    };
    let http = create_pinned_tls_client(std::slice::from_ref(pin))?;
    let client = client.with_http_client(http.clone());

    let mut model_attestations = Vec::new();
    if model.provider == "near" {
        let fetched_model_attestations = client
            .fetch_model_attestations(&model.id, Some(signing_algo), None)
            .await?;
        assert!(
            !fetched_model_attestations.attestations.is_empty(),
            "Expected NEAR model evidence"
        );
        for attestation in &fetched_model_attestations.attestations {
            let verified = verify_model_attestation(
                attestation,
                &fetched_model_attestations.client_binding,
                None,
                Default::default(),
            )
            .await?;
            assert_eq!(verified.gpu_evidence, GpuEvidenceStatus::Verified);
            model_attestations.push(verified);
        }
    }

    let selected_attestation = model_attestations.iter().find(|report| {
        report.evidence.signer.signing_algo == signing_algo && report.signing_public_key.is_some()
    });
    if model.provider == "near" {
        assert!(
            selected_attestation.is_some(),
            "Expected a verified model key"
        );
    }
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    for stream in [false, true] {
        // Chutes returns a Gateway receipt. Streaming is separately provider-gated,
        // so its live case uses JSON only.
        if model.provider == "chutes" && stream {
            continue;
        }
        let request_body = serde_json::to_vec(&json!({
            "model": model.id,
            "messages": [{"role": "user", "content": "Reply with the single word OK."}],
            // Reasoning tokens share this budget; leave room for a visible answer.
            "max_completion_tokens": 1024,
            "stream": stream,
        }))?;
        let mut request = http
            .post(&url)
            .bearer_auth(&api_key)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT_ENCODING, "identity")
            .header("x-no-aliasing", "true")
            .body(request_body.clone());
        if let Some(attestation) = selected_attestation {
            request = request.header(
                "X-Model-Pub-Key",
                attestation.signing_public_key.as_ref().unwrap(),
            );
        }
        let response = request.send().await?;
        assert!(
            response.status().is_success(),
            "Chat returned HTTP {}",
            response.status()
        );
        let response_body = response.bytes().await?;
        let id = read_completion_id(&response_body, stream)?;
        let signature = fetch_signature_with_retry(&client, &id, signing_algo).await?;
        assert_eq!(signature.signer.signing_algo, signing_algo);
        if model.provider != "near" {
            assert_eq!(signature.kind, CompletionSignatureKind::Gateway);
        }

        // The signature must cover the exact wire bytes, including whitespace.
        let mut altered = response_body.to_vec();
        altered.push(b' ');
        match signature.kind {
            CompletionSignatureKind::ProviderTee => {
                let attestation = selected_attestation.expect("Expected a verified model key");
                verify_model_response(&request_body, &response_body, &signature, attestation)?;
                let matching_attestations =
                    find_model_attestations_for_signature(&model_attestations, &signature)?;
                let expected: Vec<_> = model_attestations
                    .iter()
                    .filter(|report| {
                        same_signer(&report.evidence.signer, &attestation.evidence.signer)
                    })
                    .collect();
                assert_eq!(matching_attestations, expected);
                assert!(
                    verify_model_response(&request_body, &altered, &signature, attestation)
                        .is_err()
                );
            }
            CompletionSignatureKind::Gateway => {
                verify_gateway_response(&request_body, &response_body, &signature, &gateway)?;
                assert!(
                    verify_gateway_response(&request_body, &altered, &signature, &gateway).is_err()
                );
            }
        }
        println!(
            "{signing_algo}, stream={stream}: verified deployment and {:?} receipt",
            signature.kind
        );
    }
    Ok(())
}

async fn fetch_signature_with_retry(
    client: &AttestationClient,
    id: &str,
    signing_algo: SigningAlgo,
) -> Result<CompletionSignature, ApiError> {
    // Retry receipt propagation only. Never repeat Chat or cryptographic checks.
    for backoff_ms in [500, 1_000, 2_000, 4_000] {
        match client
            .fetch_completion_signature(id, Some(signing_algo))
            .await
        {
            Err(error) if error.retryable() => {
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
            result => return result,
        }
    }
    client
        .fetch_completion_signature(id, Some(signing_algo))
        .await
}

fn read_completion_id(response_body: &[u8], stream: bool) -> Result<String, Box<dyn Error>> {
    if !stream {
        let completion: Value = serde_json::from_slice(response_body)?;
        let content = completion["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(
            completion["choices"][0]["finish_reason"].as_str(),
            Some("stop")
        );
        assert!(
            !content.trim().is_empty(),
            "Expected non-empty Chat content"
        );
        return completion_id(&completion);
    }

    let events = sse_data(response_body)?;
    assert_eq!(
        events.last().map(String::as_str),
        Some("[DONE]"),
        "Expected a complete SSE response"
    );
    let mut id = None;
    let mut content = String::new();
    let mut finish_reason = None;
    for event in events.into_iter().filter(|event| *event != "[DONE]") {
        let chunk: Value = serde_json::from_str(&event)?;
        let chunk_id = completion_id(&chunk)?;
        if let Some(id) = &id {
            assert_eq!(id, &chunk_id);
        } else {
            id = Some(chunk_id);
        }
        content.push_str(
            chunk["choices"][0]["delta"]["content"]
                .as_str()
                .unwrap_or_default(),
        );
        if let Some(reason) = chunk["choices"][0]["finish_reason"].as_str() {
            finish_reason = Some(reason.to_owned());
        }
    }
    assert_eq!(
        finish_reason.as_deref(),
        Some("stop"),
        "SSE must complete without truncation"
    );
    assert!(
        !content.trim().is_empty(),
        "Expected non-empty Chat content"
    );
    id.ok_or_else(|| io::Error::other("SSE has no completion ID").into())
}

fn completion_id(value: &Value) -> Result<String, Box<dyn Error>> {
    value["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("Chat has no completion ID").into())
}

fn required_env(name: &str) -> Result<String, io::Error> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other(format!("{name} is required for live E2E tests")))
}

fn sse_data(bytes: &[u8]) -> Result<Vec<String>, std::str::Utf8Error> {
    let text = std::str::from_utf8(bytes)?
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let records: Vec<_> = text.split("\n\n").collect();
    Ok(records[..records.len() - 1]
        .iter()
        .filter_map(|record| {
            let data = record
                .split('\n')
                .filter_map(|line| {
                    if line == "data" {
                        Some("")
                    } else {
                        line.strip_prefix("data:")
                            .map(|value| value.strip_prefix(' ').unwrap_or(value))
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            if data.is_empty() {
                None
            } else {
                Some(data)
            }
        })
        .collect())
}
