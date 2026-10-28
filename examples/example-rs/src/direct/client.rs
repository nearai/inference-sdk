// Experimental direct JSON/SSE with E2EE. Use Gateway clients for production.
use example_rs::*;
use nearai_inference_sdk::*;
#[tokio::main]
async fn main() -> Result<()> {
    // Requires a credential accepted by this endpoint; Gateway keys may differ.
    let client = DirectInferenceClient::with_options(DirectInferenceClientOptions {
        api_key: Some(api_key()?),
        base_url: direct(),
        signing_algo: algo()?,
        e2ee: true,
        ohttp: ohttp(),
        // Optional OHTTP requires Ed25519 and signed configuration.
        ..Default::default()
    })?;
    let verified = client.verify(&model()).await?;
    println!("Verified {} model reports", verified.attestations.len());
    // Direct TLS evidence fetching is disabled; ordinary HTTPS validation applies.
    for stream in [false, true] {
        let bytes = if stream {
            let response = client.send(client.chat_request(body(true))?).await?;
            if !response.status.is_success() {
                return Err(format!("Chat failed: {}", response.status).into());
            }
            read_stream(response.body).await?
        } else {
            serde_json::to_vec(&client.chat_completions(body(false)).await?)?
        };
        let id = completion_id(&bytes, stream)?;
        client.verify_response(&id).await?;
        println!("Verified direct receipt");
        display(&bytes, stream)?;
    }
    Ok(())
}
