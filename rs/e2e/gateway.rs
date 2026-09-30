use std::{env, error::Error, io, time::Duration};

use nearai_inference_sdk::{
    find_model_attestation_for_signature, verify_gateway_attestation, verify_gateway_response,
    verify_model_attestation, verify_model_response, ApiError, AttestationClient,
    CompletionSignature, CompletionSignatureKind, GatewayAttestationFetchOptions,
    GatewayTlsBinding, GpuEvidenceStatus, SigningAlgo,
};
use reqwest::header::{ACCEPT_ENCODING, CONTENT_TYPE};
use serde_json::{json, Value};

#[tokio::test]
#[ignore = "requires NEARAI_E2E_BASE_URL and NEARAI_E2E_API_KEY"]
async fn ed25519_gateway_chat_receipts() -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(180), verify_chat(SigningAlgo::Ed25519)).await?
}

#[tokio::test]
#[ignore = "requires NEARAI_E2E_BASE_URL and NEARAI_E2E_API_KEY"]
async fn ecdsa_gateway_chat_receipts() -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(180), verify_chat(SigningAlgo::Ecdsa)).await?
}

async fn verify_chat(signing_algo: SigningAlgo) -> Result<(), Box<dyn Error>> {
    let base_url = required_env("NEARAI_E2E_BASE_URL")?;
    let api_key = required_env("NEARAI_E2E_API_KEY")?;
    let model = env::var("NEARAI_E2E_MODEL")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "z-ai/glm-5.3-flash".to_owned());
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

    let fetched_models = client
        .fetch_model_attestations(&model, Some(signing_algo), None)
        .await?;
    assert!(
        !fetched_models.attestations.is_empty(),
        "Expected NEAR model evidence"
    );
    let mut models = Vec::new();
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

    let http = reqwest::Client::new();
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    for stream in [false, true] {
        let request_body = serde_json::to_vec(&json!({
            "model": model,
            "messages": [{"role": "user", "content": "Reply with the single word OK."}],
            "max_completion_tokens": 128,
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
        assert!(
            content.to_uppercase().contains("OK"),
            "Expected Chat content"
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
    }
    assert!(
        content.to_uppercase().contains("OK"),
        "Expected Chat content"
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
