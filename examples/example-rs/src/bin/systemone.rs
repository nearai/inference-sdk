use example_rs::*;
use nearai_inference_sdk::*;
use serde_json::json;

async fn run() -> Result<()> {
    let model = std::env::var("NEARAI_MODEL")?;
    let expected = match std::env::var("NEARAI_EXPECT_SIGNATURE_KIND")
        .as_deref()
        .unwrap_or("gateway")
    {
        "gateway" => CompletionSignatureKind::Gateway,
        "provider_tee" => CompletionSignatureKind::ProviderTee,
        _ => return Err("NEARAI_EXPECT_SIGNATURE_KIND must be gateway or provider_tee".into()),
    };
    let client = InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(api_key()?),
        base_url: gateway(),
        signing_algo: algo()?,
        model_verification: ModelVerificationOptions {
            policy: (expected == CompletionSignatureKind::ProviderTee).then(Default::default),
            ..Default::default()
        },
        ..Default::default()
    })?;
    let mut request = json!({
        "state": {
            "message": "I was charged twice for my subscription. Please help."
        },
        "questions": {
            "billing": {
                "type": "noul",
                "instructions": "Is this about billing?"
            },
            "team": {
                "type": "choice",
                "instructions": "Which team should handle this?",
                "criteria": {
                    "billing": "Payments and subscriptions",
                    "support": "Technical issues"
                }
            },
            "urgency": {
                "type": "score",
                "instructions": "How urgent is this request?",
                "criteria": [
                    "Routine",
                    "Needs prompt attention",
                    "Critical"
                ]
            }
        }
    });
    request["model"] = json!(model);
    let result = client.systemone_create(&request).await?;
    let receipt = client.verify_response(&result.decision_id).await?;
    if receipt.signature_kind() != expected {
        return Err("Unexpected signature kind".into());
    }
    println!(
        "Verified {:?} receipt {}.",
        receipt.signature_kind(),
        result.decision_id
    );
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"answers": result.data.answers, "usage": result.data.usage})
        )?
    );
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(120), run()).await?
}
