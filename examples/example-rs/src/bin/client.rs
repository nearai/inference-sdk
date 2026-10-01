//! Integrated Gateway Chat; run with NEARAI_API_KEY and optionally NEARAI_MODEL.
use nearai_inference_sdk::{InferenceClient, InferenceClientOptions};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let model = std::env::var("NEARAI_MODEL").unwrap_or_else(|_| "z-ai/glm-5.3-flash".into());
    let client = InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(std::env::var("NEARAI_API_KEY")?),
        e2ee: true,
        ..Default::default()
    })?;
    let deployments = client.verify(&model).await?;
    println!("Deployment verified at {}", deployments.verified_at);
    let completion = client
        .chat_completions(json!({
            "model": model,
            "messages": [{"role": "user", "content": "Hello!"}]
        }))
        .await?;
    let id = completion["id"].as_str().ok_or("missing completion ID")?;
    let verified = client.verify_response(id).await?;
    println!("Verified {:?} response", verified.signature_kind());
    println!("{}", completion["choices"][0]["message"]["content"]);
    Ok(())
}
