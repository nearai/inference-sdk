use nearai_inference_sdk::{
    CompletionSignatureKind, InferenceClient, InferenceClientOptions, SigningAlgo,
};
use serde_json::{json, Value};
use std::{error::Error, time::Duration};

#[tokio::test]
#[ignore = "requires NEARAI_BASE_URL, NEARAI_API_KEY and NEARAI_E2E_MODELS"]
async fn verified_messages_json_and_sse() -> Result<(), Box<dyn Error>> {
    let models = super::select_models(&super::required_env("NEARAI_E2E_MODELS")?, "messages")?;
    assert_eq!(models.len(), 1, "Expected one Anthropic Messages model");
    for (algo, ohttp) in [
        (SigningAlgo::Ed25519, false),
        (SigningAlgo::Ecdsa, false),
        (SigningAlgo::Ed25519, true),
    ] {
        tokio::time::timeout(
            Duration::from_secs(180),
            verify_messages(&models[0].id, algo, ohttp),
        )
        .await??;
    }
    Ok(())
}

async fn verify_messages(
    model: &str,
    signing_algo: SigningAlgo,
    ohttp: bool,
) -> Result<(), Box<dyn Error>> {
    let client = InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(super::required_env("NEARAI_API_KEY")?),
        base_url: super::required_env("NEARAI_BASE_URL")?,
        signing_algo,
        ohttp,
        ..Default::default()
    })?;
    for stream in [false, true] {
        let request = json!({
            "model": model, "max_tokens": 128, "stream": stream,
            "messages": [{"role": "user", "content": "Reply with the word OK."}],
        });
        let (id, text) = if stream {
            let response = client.send(client.message_request(request)?).await?;
            assert!(response.status.is_success());
            let bytes = response.bytes().await?;
            let events: Vec<Value> = super::sse_data(&bytes)?
                .into_iter()
                .filter(|data| data != "[DONE]")
                .map(|data| serde_json::from_str(&data))
                .collect::<Result<_, _>>()?;
            let start = events
                .iter()
                .find(|event| event["type"] == "message_start")
                .ok_or("missing message_start")?;
            let id = start["message"]["id"]
                .as_str()
                .ok_or("missing message ID")?
                .to_owned();
            assert!(
                events.iter().any(|event| event["type"] == "message_stop"),
                "SSE must reach message_stop and EOF"
            );
            assert!(events.iter().any(|event| event["type"] == "message_delta"
                && event["delta"]["stop_reason"] == "end_turn"));
            let text: String = events
                .iter()
                .filter(|event| {
                    event["type"] == "content_block_delta" && event["delta"]["type"] == "text_delta"
                })
                .filter_map(|event| event["delta"]["text"].as_str())
                .collect();
            (id, text)
        } else {
            let message = client.create_message(request).await?;
            assert_eq!(message["type"], "message");
            assert_eq!(message["stop_reason"], "end_turn");
            let id = message["id"]
                .as_str()
                .ok_or("missing message ID")?
                .to_owned();
            let text: String = message["content"]
                .as_array()
                .ok_or("missing content")?
                .iter()
                .filter(|block| block["type"] == "text")
                .filter_map(|block| block["text"].as_str())
                .collect();
            (id, text)
        };
        assert!(
            !id.is_empty() && !text.trim().is_empty(),
            "Expected a nonempty complete Messages answer"
        );
        let receipt = tokio::time::timeout(
            Duration::from_secs(15),
            super::integrated::verify_receipt_with_retry(&client, &id),
        )
        .await??;
        assert_eq!(receipt.id, id);
        assert_eq!(receipt.signature.signer.signing_algo, signing_algo);
        assert_eq!(receipt.signature_kind(), CompletionSignatureKind::Gateway);
        println!("Messages model={model}, stream={stream}, signing_algo={signing_algo}, ohttp={ohttp}: verified Gateway receipt");
    }
    Ok(())
}
