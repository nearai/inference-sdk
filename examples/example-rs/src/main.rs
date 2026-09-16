use std::{env, error::Error, io};

use nearai_inference_sdk::{
    find_model_attestation_for_signature, verify_gateway_attestation, verify_gateway_response,
    verify_model_attestation, verify_model_response, AttestationClient, CompletionSignatureKind,
    GatewayAttestationFetchOptions, SigningAlgo, VerifiedGatewayAttestation,
    VerifiedModelAttestation, NO_ALIASING_HEADER,
};
use reqwest::header::{ACCEPT_ENCODING, CONTENT_TYPE};
use serde_json::{json, Value};

const API_URL: &str = "https://cloud-api.near.ai/v1/chat/completions";
const MODEL: &str = "z-ai/glm-5.3-flash";

struct Completion {
    completion_id: String,
    request_body: Vec<u8>,
    response_body: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let api_key =
        env::var("NEARAI_API_KEY").map_err(|_| io::Error::other("NEARAI_API_KEY is required"))?;
    let completion_client = reqwest::Client::new();
    let attestation_client = AttestationClient::new(api_key.clone());

    let verified_gateway = verify_gateway_deployment(&attestation_client).await?;
    let verified_models = verify_model_deployments(&attestation_client).await?;

    let non_streaming = send_completion(&completion_client, &api_key, false).await?;
    verify_completion_receipt(
        &attestation_client,
        &non_streaming,
        &verified_gateway,
        &verified_models,
        false,
    )
    .await?;

    let streaming = send_completion(&completion_client, &api_key, true).await?;
    verify_completion_receipt(
        &attestation_client,
        &streaming,
        &verified_gateway,
        &verified_models,
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

async fn verify_model_deployments(
    client: &AttestationClient,
) -> Result<Vec<VerifiedModelAttestation>, Box<dyn Error>> {
    let fetched = client
        .fetch_model_attestations(MODEL, Some(SigningAlgo::Ecdsa), None)
        .await?;
    if fetched.attestations.is_empty() {
        return Err(io::Error::other("Cloud API returned no model attestations").into());
    }

    let mut verified = Vec::with_capacity(fetched.attestations.len());
    for attestation in &fetched.attestations {
        verified.push(
            verify_model_attestation(
                attestation,
                &fetched.client_binding,
                None,
                Default::default(),
            )
            .await?,
        );
    }

    println!("Model deployments: verified {}.", verified.len());
    Ok(verified)
}

async fn send_completion(
    completion_client: &reqwest::Client,
    api_key: &str,
    stream: bool,
) -> Result<Completion, Box<dyn Error>> {
    let request_body = serde_json::to_vec(&json!({
        "model": MODEL,
        "messages": [{ "role": "user", "content": "Reply with the word ok." }],
        "stream": stream,
        "max_completion_tokens": 8,
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
    Ok(Completion {
        completion_id,
        request_body,
        response_body,
    })
}

async fn verify_completion_receipt(
    attestation_client: &AttestationClient,
    completion: &Completion,
    verified_gateway: &VerifiedGatewayAttestation,
    verified_models: &[VerifiedModelAttestation],
    stream: bool,
) -> Result<(), Box<dyn Error>> {
    let signature = attestation_client
        .fetch_completion_signature(&completion.completion_id, Some(SigningAlgo::Ecdsa))
        .await?;
    let label = if stream { "Streaming" } else { "Non-streaming" };

    // Both deployments were verified before chat. The receipt kind selects
    // which verified signer covers these exact response bytes.
    match signature.kind {
        CompletionSignatureKind::ProviderTee => {
            let verified_model = find_model_attestation_for_signature(verified_models, &signature)?;
            verify_model_response(
                &completion.request_body,
                &completion.response_body,
                &signature,
                verified_model,
            )?;
            println!("{label}: verified a model-serving TEE receipt.");
        }
        CompletionSignatureKind::Gateway => {
            verify_gateway_response(
                &completion.request_body,
                &completion.response_body,
                &signature,
                verified_gateway,
            )?;
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
