use example_rs::*;
use nearai_inference_sdk::{InferenceClient, InferenceClientOptions};
use serde_json::json;

async fn run() -> Result<()> {
    let client = InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(api_key()?),
        base_url: gateway(),
        signing_algo: algo()?,
        ohttp: ohttp(),
        ..Default::default()
    })?;
    let model = std::env::var("NEARAI_MODEL").unwrap_or_else(|_| "z-ai/glm-5.3-flash".into());
    let mut request = json!({"model": model, "input":"Reply with the word ok.", "max_output_tokens": 1024, "store": false});
    let response = client.create_response(request.clone()).await?;
    let id = response["id"].as_str().ok_or("missing response ID")?;
    let receipt = client.verify_response(id).await?;
    println!("Verified {:?} response.", receipt.signature_kind());
    println!(
        "{}",
        response["output"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|item| item["content"].as_array().into_iter().flatten())
            .filter_map(|block| block["text"].as_str())
            .collect::<String>()
    );

    request["stream"] = json!(true);
    let response = client.send(client.response_request(request)?).await?;
    if !response.status.is_success() {
        return Err(format!("HTTP status: {}", response.status).into());
    }
    let events = events(&read_stream(response.body).await?)?;
    let id = events
        .iter()
        .find_map(|event| event["response"]["id"].as_str())
        .ok_or("missing response ID")?;
    let receipt = client.verify_response(id).await?;
    println!(
        "Verified {:?} streaming response.",
        receipt.signature_kind()
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(120), run()).await?
}
