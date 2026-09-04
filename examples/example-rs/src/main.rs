use std::{env, error::Error, io};

use reqwest::header::{ACCEPT_ENCODING, CONTENT_TYPE};
use serde_json::{json, Value};
use verifiable_ai_sdk::{
    verify_gateway_attestation, verify_gateway_response, verify_model_attestation,
    verify_model_response, AttestationClient, CompletionSignatureKind,
    GatewayAttestationFetchOptions, SigningAlgo, VerifiedGatewayAttestation,
    VerifiedModelAttestation, NO_ALIASING_HEADER,
};

const API_URL: &str = "https://cloud-api.near.ai/v1/chat/completions";
const MODEL: &str = "z-ai/glm-5.2";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let api_key =
        env::var("NEARAI_API_KEY").map_err(|_| io::Error::other("NEARAI_API_KEY is required"))?;
    let completion_client = reqwest::Client::new();
    let attestation_client = AttestationClient::new(api_key.clone());

    let verified_gateway = verify_gateway_deployment(&attestation_client).await?;
    let verified_model = verify_model_deployment(&attestation_client).await?;

    verify_completion(
        &completion_client,
        &attestation_client,
        &api_key,
        &verified_gateway,
        &verified_model,
        false,
    )
    .await?;
    verify_completion(
        &completion_client,
        &attestation_client,
        &api_key,
        &verified_gateway,
        &verified_model,
        true,
    )
    .await?;
    Ok(())
}

async fn verify_gateway_deployment(
    client: &AttestationClient,
) -> Result<VerifiedGatewayAttestation, Box<dyn Error>> {
    let fetched = client
        .fetch_gateway_attestation(GatewayAttestationFetchOptions {
            signing_algo: Some(SigningAlgo::Ecdsa),
            ..Default::default()
        })
        .await?;
    let verified = verify_gateway_attestation(
        &fetched.attestation,
        &fetched.client_binding,
        None,
        Default::default(),
    )
    .await?;
    println!("Gateway deployment: verified.");
    Ok(verified)
}

async fn verify_model_deployment(
    client: &AttestationClient,
) -> Result<VerifiedModelAttestation, Box<dyn Error>> {
    let fetched = client
        .fetch_model_attestations(MODEL, Some(SigningAlgo::Ecdsa), None)
        .await?;
    let attestation = fetched
        .attestations
        .first()
        .ok_or_else(|| io::Error::other("Cloud API returned no model attestation"))?;
    let verified = verify_model_attestation(
        attestation,
        &fetched.client_binding,
        None,
        Default::default(),
    )
    .await?;
    println!("Model deployment: verified.");
    Ok(verified)
}

async fn verify_completion(
    completion_client: &reqwest::Client,
    attestation_client: &AttestationClient,
    api_key: &str,
    verified_gateway: &VerifiedGatewayAttestation,
    verified_model: &VerifiedModelAttestation,
    stream: bool,
) -> Result<(), Box<dyn Error>> {
    let request_body = serde_json::to_vec(&json!({
        "model": MODEL,
        "messages": [{ "role": "user", "content": "Reply with the word ok." }],
        "stream": stream,
        "max_tokens": 8,
    }))?;
    let completion_response = completion_client
        .post(API_URL)
        .bearer_auth(api_key)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT_ENCODING, "identity")
        .header(NO_ALIASING_HEADER, "true")
        .body(request_body.clone())
        .send()
        .await?;
    let status = completion_response.status();
    let response_body = completion_response.bytes().await?.to_vec();
    if !status.is_success() {
        return Err(io::Error::other(format!(
            "Completion request failed ({status}): {}",
            String::from_utf8_lossy(&response_body)
        ))
        .into());
    }

    // Keep these original bytes unchanged for response-signature verification.
    let completion_id = read_completion_id(&response_body, stream)?;
    let signature = attestation_client
        .fetch_completion_signature(&completion_id, Some(SigningAlgo::Ecdsa))
        .await?;
    let label = if stream { "Streaming" } else { "Non-streaming" };

    // Both deployments were verified before chat. The receipt kind selects
    // which verified signer covers these exact response bytes.
    match signature.kind {
        CompletionSignatureKind::ProviderTee => {
            verify_model_response(&request_body, &response_body, &signature, verified_model)?;
            println!("{label}: verified a model-serving TEE receipt.");
        }
        CompletionSignatureKind::Gateway => {
            verify_gateway_response(&request_body, &response_body, &signature, verified_gateway)?;
            println!("{label}: verified a Gateway receipt.");
        }
    }

    Ok(())
}

fn read_completion_id(response_body: &[u8], stream: bool) -> Result<String, Box<dyn Error>> {
    if !stream {
        let completion: Value = serde_json::from_slice(response_body)?;
        return completion
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| io::Error::other("Completion response did not contain an id").into());
    }

    for line in std::str::from_utf8(response_body)?.lines() {
        let Some(event) = line.strip_prefix("data: ") else {
            continue;
        };
        if event == "[DONE]" {
            continue;
        }
        let Ok(event) = serde_json::from_str::<Value>(event) else {
            continue;
        };
        if let Some(completion_id) = event.get("id").and_then(Value::as_str) {
            return Ok(completion_id.to_owned());
        }
    }
    Err(io::Error::other("Streaming completion response did not contain an id").into())
}
