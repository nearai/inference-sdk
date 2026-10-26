use example_rs::*;
use futures_util::StreamExt;
use nearai_inference_sdk::{ByteStream, InferenceClient, InferenceClientOptions};
use serde_json::json;
use std::io::{self, Write};

async fn display_stream(mut body: ByteStream, output: &mut impl Write) -> Result<String> {
    let mut id = None;
    while let Some(record) = body.next().await {
        for event in events(&record?)? {
            if event["type"] == "message_start" {
                id = event["message"]["id"].as_str().map(str::to_owned);
            }
            if event["type"] == "content_block_delta" && event["delta"]["type"] == "text_delta" {
                write!(
                    output,
                    "{}",
                    event["delta"]["text"].as_str().unwrap_or_default()
                )?;
                output.flush()?;
            }
        }
    }
    writeln!(output)?;
    id.ok_or_else(|| "missing response ID".into())
}

async fn run() -> Result<()> {
    let client = InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(api_key()?),
        base_url: gateway(),
        signing_algo: algo()?,
        ohttp: ohttp(),
        ..Default::default()
    })?;
    let model =
        std::env::var("NEARAI_MODEL").unwrap_or_else(|_| "anthropic/claude-haiku-4-5".into());
    let request = json!({
        "model": model,
        "messages": [{"role": "user", "content": "Reply with the word ok."}],
        "max_tokens": 128
    });
    let response = client.create_message(request.clone()).await?;
    let id = response["id"].as_str().ok_or("missing response ID")?;
    let verified = client.verify_response(id).await?;
    println!("Verified {:?} response.", verified.signature_kind());
    println!(
        "{}",
        response["content"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|block| block["text"].as_str())
            .collect::<String>()
    );

    let mut request = request;
    request["stream"] = json!(true);
    let response = client.send(client.message_request(request)?).await?;
    if !response.status.is_success() {
        return Err(format!("Messages HTTP status: {}", response.status).into());
    }
    // Display text as it arrives, then verify only after consuming the full body.
    let id = display_stream(response.body, &mut io::stdout()).await?;
    let verified = client.verify_response(&id).await?;
    println!(
        "Verified {:?} streaming response.",
        verified.signature_kind()
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(120), run()).await?
}
