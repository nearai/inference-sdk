use nearai_inference_sdk::{
    CompletionSignatureKind, InferenceClient, InferenceClientOptions, SigningAlgo,
};
use serde_json::{json, Value};
use std::{error::Error, time::Duration};

#[tokio::test]
#[ignore = "requires NEARAI_BASE_URL, NEARAI_API_KEY and NEARAI_E2E_MODELS"]
async fn verified_responses_json_and_sse() -> Result<(), Box<dyn Error>> {
    let models = super::select_models(&super::required_env("NEARAI_E2E_MODELS")?, "responses")?;
    assert_eq!(models.len(), 2, "Expected NEAR and OpenAI Responses models");

    for model in models {
        for (algo, ohttp) in [
            (SigningAlgo::Ed25519, false),
            (SigningAlgo::Ecdsa, false),
            (SigningAlgo::Ed25519, true),
        ] {
            tokio::time::timeout(
                Duration::from_secs(180),
                verify_responses(&model.id, algo, ohttp),
            )
            .await??;
        }
    }

    Ok(())
}

async fn verify_responses(
    model: &str,
    signing_algo: SigningAlgo,
    ohttp: bool,
) -> Result<(), Box<dyn Error>> {
    let client = InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(super::required_env("NEARAI_API_KEY")?),
        base_url: super::required_env("NEARAI_BASE_URL")?,
        ohttp,
        signing_algo,
        ..Default::default()
    })?;

    for stream in [false, true] {
        let request = json!({
            "model": model,
            "input": "Reply with the word OK.",
            "store": false,
            "max_output_tokens": 1024,
            "stream": stream,
        });

        let result = if stream {
            let response = client.send(client.response_request(request)?).await?;
            assert!(response.status.is_success());
            let bytes = response.bytes().await?;
            let events: Vec<Value> = super::sse_data(&bytes)?
                .into_iter()
                .filter(|data| data != "[DONE]")
                .map(|data| serde_json::from_str(&data))
                .collect::<Result<_, _>>()?;
            let created = events
                .iter()
                .find(|e| e["type"] == "response.created")
                .ok_or("missing response.created")?;
            let completed = events
                .iter()
                .find(|e| e["type"] == "response.completed")
                .ok_or("missing response.completed")?;
            assert_eq!(created["response"]["id"], completed["response"]["id"]);
            completed["response"].clone()
        } else {
            client.create_response(request).await?
        };

        assert_eq!(result["status"], "completed");
        assert!(!result["output"]
            .as_array()
            .ok_or("missing output")?
            .is_empty());

        let id = result["id"].as_str().ok_or("missing response ID")?;
        let receipt = tokio::time::timeout(
            Duration::from_secs(15),
            super::integrated::verify_receipt_with_retry(&client, id),
        )
        .await??;

        assert_eq!(receipt.id, id);
        assert_eq!(receipt.signature.signer.signing_algo, signing_algo);
        assert_eq!(receipt.signature_kind(), CompletionSignatureKind::Gateway);
        println!(
            "Responses model={model}, stream={stream}, ohttp={ohttp}: verified Gateway receipt"
        );
    }

    Ok(())
}
