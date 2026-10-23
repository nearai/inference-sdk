use nearai_inference_sdk::InferenceClient;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = InferenceClient::new(std::env::var("NEARAI_API_KEY")?)?;
    let request = json!({
        "model": "z-ai/glm-5.3-flash",
        "input": "Reply with the word ok.",
        "store": false
    });
    let response = client.create_response(request.clone()).await?;
    let id = response["id"].as_str().ok_or("missing response ID")?;
    client.verify_response(id).await?;
    println!("{}", response["output"]);

    let mut request = request;
    request["stream"] = json!(true);
    let response = client.send(client.response_request(request)?).await?;
    if !response.status.is_success() {
        return Err(format!("Responses HTTP status: {}", response.status).into());
    }
    // Applications can decode SSE incrementally through response.body. This
    // example buffers to EOF, then reads the lifecycle event's response ID.
    let bytes = response.bytes().await?;
    let text = std::str::from_utf8(&bytes)?;
    let id = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find_map(|event| event["response"]["id"].as_str().map(str::to_owned))
        .ok_or("missing response ID")?;
    client.verify_response(&id).await?;
    println!("{text}");
    Ok(())
}
