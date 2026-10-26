use futures_util::StreamExt;
use nearai_inference_sdk::{ByteStream, InferenceClient};
use serde_json::{json, Value};
use std::io::{self, Write};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// The verified SDK stream yields complete SSE records, including their data lines.
fn message_events(record: &[u8]) -> Result<Vec<Value>> {
    let text = std::str::from_utf8(record)?
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut events = Vec::new();
    for record in text.split("\n\n") {
        let data = record
            .split('\n')
            .filter_map(|line| {
                if line == "data" {
                    Some("")
                } else {
                    line.strip_prefix("data:")
                        .map(|value| value.strip_prefix(' ').unwrap_or(value))
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        if !data.is_empty() {
            events.push(serde_json::from_str(&data)?);
        }
    }
    Ok(events)
}

async fn display_stream(mut body: ByteStream, output: &mut impl Write) -> Result<String> {
    let mut id = None;
    while let Some(record) = body.next().await {
        for event in message_events(&record?)? {
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

#[tokio::main]
async fn main() -> Result<()> {
    let client = InferenceClient::new(std::env::var("NEARAI_API_KEY")?)?;
    let request = json!({
        "model": "anthropic/claude-haiku-4-5",
        "messages": [{"role": "user", "content": "Reply with the word ok."}],
        "max_tokens": 128
    });
    let response = client.create_message(request.clone()).await?;
    let id = response["id"].as_str().ok_or("missing response ID")?;
    client.verify_response(id).await?;
    println!("{}", response["content"]);

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
