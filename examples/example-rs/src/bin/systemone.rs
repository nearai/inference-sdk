use nearai_inference_sdk::{InferenceClient, InferenceClientOptions};
use serde_json::json;
use std::{env, error::Error, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(env::var("NEARAI_API_KEY")?),
        base_url: env::var("NEARAI_BASE_URL")
            .unwrap_or_else(|_| "https://cloud-api.near.ai/v1".into()),
        ..Default::default()
    })?;
    let result = client
        .systemone_create(&json!({
            "model":env::var("NEARAI_SYSTEMONE_MODEL")?,
            "state":{"message":"I was charged twice for my subscription."},
            "questions":{"billing":{"type":"noul","instructions":"Is this about billing?"}}
        }))
        .await?;
    let mut receipt = client.verify_response(&result.decision_id).await;
    for delay in [500, 1_000, 2_000, 4_000] {
        if !receipt
            .as_ref()
            .is_err_and(|e| e.retryable() || e.code() == "api.completion_signature_unavailable")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(delay)).await;
        receipt = client.verify_response(&result.decision_id).await;
    }
    println!("Verified {:?} receipt", receipt?.signature_kind());
    println!("{}", serde_json::to_string_pretty(&result.data)?);
    Ok(())
}
