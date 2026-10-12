// Integrated Gateway JSON/SSE, E2EE, build provenance, and receipt verification.
use example_rs::*;
use nearai_inference_sdk::*;
use std::sync::Arc;
#[tokio::main]
async fn main() -> Result<()> {
    let client = InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(api_key()?),
        base_url: GATEWAY.into(),
        signing_algo: ALGO,
        e2ee: true,
        // Optional: set ohttp: true with Ed25519; both Chat modes stay the same.
        gateway_verification: GatewayVerificationOptions {
            deployment: Some(Arc::new(GatewayImages)),
            ..Default::default()
        },
        ..Default::default()
    })?;
    let verified = client.verify(MODEL).await?;
    println!(
        "Gateway/model deployments and Gateway images verified at {}",
        verified.verified_at
    );
    for stream in [false, true] {
        let bytes = if stream {
            let response = client.send(client.chat_request(body(true))?).await?;
            if !response.status.is_success() {
                return Err(format!("Chat failed: {}", response.status).into());
            }
            // Consume EOF even after [DONE], so the exact receipt is retained.
            response.bytes().await?
        } else {
            serde_json::to_vec(&client.chat_completions(body(false)).await?)?
        };
        let id = completion_id(&bytes, stream)?;
        let receipt = client.verify_response(&id).await?;
        println!("Verified {:?} receipt", receipt.signature_kind());
        display(&bytes, stream)?;
    }
    Ok(())
}
