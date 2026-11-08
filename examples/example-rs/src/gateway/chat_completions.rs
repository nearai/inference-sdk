// Integrated Gateway JSON/SSE, E2EE, and receipt verification.
use example_rs::utils::*;
use nearai_inference_sdk::*;
#[tokio::main]
async fn main() -> Result<()> {
    let client = InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(api_key()?),
        base_url: gateway(),
        signing_algo: algo()?,
        e2ee: true,
        ohttp: ohttp(),
        // Optional: set ohttp: true with Ed25519; both Chat modes stay the same.
        ..Default::default()
    })?;
    let verified = client.verify(&model()).await?;
    println!(
        "Gateway and model attestations verified at {}",
        verified.verified_at
    );
    for stream in [false, true] {
        let bytes = if stream {
            let response = client.send(client.chat_request(body(true))?).await?;
            if !response.status.is_success() {
                return Err(format!("Chat failed: {}", response.status).into());
            }
            // Consume EOF even after [DONE], so the exact receipt is retained.
            read_stream(response.body).await?
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
