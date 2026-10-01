mod integrated;

use std::{env, error::Error, io, time::Duration};

use nearai_inference_sdk::{
    find_model_attestation_for_signature, verify_gateway_attestation, verify_gateway_response,
    verify_model_attestation, verify_model_response, ApiError, AttestationClient,
    CompletionSignature, CompletionSignatureKind, GatewayAttestationFetchOptions,
    GatewayTlsBinding, GpuEvidenceStatus, SigningAlgo,
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
}

async fn verify_models(signing_algo: SigningAlgo) -> Result<(), Box<dyn Error>> {
    let models: Vec<LiveModel> = serde_json::from_str(&required_env("NEARAI_E2E_MODELS")?)?;
    assert!(!models.is_empty(), "Expected representative Chat models");
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

    let mut models = Vec::new();
    if model.provider == "near" {
        let fetched_models = client
            .fetch_model_attestations(&model.id, Some(signing_algo), None)
            .await?;
        assert!(
            !fetched_models.attestations.is_empty(),
            "Expected NEAR model evidence"
        );
        for attestation in &fetched_models.attestations {
            let verified = verify_model_attestation(
                attestation,
                &fetched_models.client_binding,
                None,
                Default::default(),
            )
            .await?;
            assert_eq!(verified.gpu_evidence, GpuEvidenceStatus::Verified);
            models.push(verified);
        }
    }

    let http = reqwest::Client::new();
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
        let response = http
            .post(&url)
            .bearer_auth(&api_key)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT_ENCODING, "identity")
            .header("x-no-aliasing", "true")
            .body(request_body.clone())
            .send()
            .await?;
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
                let attestation = find_model_attestation_for_signature(&models, &signature)?;
                verify_model_response(&request_body, &response_body, &signature, attestation)?;
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

    let events: Vec<_> = std::str::from_utf8(response_body)?
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .collect();
    assert_eq!(
        events.last().copied(),
        Some("[DONE]"),
        "Expected a complete SSE response"
    );
    let mut id = None;
    let mut content = String::new();
    let mut finish_reason = None;
    for event in events.into_iter().filter(|event| *event != "[DONE]") {
        let chunk: Value = serde_json::from_str(event)?;
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
