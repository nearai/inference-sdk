//! Real Gateway coverage for the integrated transport; never use mock verifiers.
use super::{read_completion_id, required_env, LiveModel};
use nearai_inference_sdk::{
    CompletionSignatureKind, GatewayTlsBinding, GpuEvidenceStatus, InferenceClient,
    InferenceClientOptions, InferenceError, SigningAlgo, VerifiedCompletionResult,
};
use serde_json::json;
use std::{error::Error, io, time::Duration};

#[tokio::test]
#[ignore = "requires NEARAI_BASE_URL, NEARAI_API_KEY and NEARAI_E2E_MODELS"]
async fn unencrypted_chat_receipts() -> Result<(), Box<dyn Error>> {
    verify_models(false, SigningAlgo::Ed25519, false).await
}

#[tokio::test]
#[ignore = "requires NEARAI_BASE_URL, NEARAI_API_KEY and NEARAI_E2E_MODELS"]
async fn ed25519_e2ee_chat_receipts() -> Result<(), Box<dyn Error>> {
    verify_models(true, SigningAlgo::Ed25519, false).await
}

#[tokio::test]
#[ignore = "requires NEARAI_BASE_URL, NEARAI_API_KEY and NEARAI_E2E_MODELS"]
async fn ecdsa_e2ee_chat_receipts() -> Result<(), Box<dyn Error>> {
    verify_models(true, SigningAlgo::Ecdsa, false).await
}

#[tokio::test]
#[ignore = "requires NEARAI_BASE_URL, NEARAI_API_KEY and NEARAI_E2E_MODELS"]
async fn ohttp_e2ee_chat_receipts() -> Result<(), Box<dyn Error>> {
    verify_models(true, SigningAlgo::Ed25519, true).await
}

async fn verify_models(
    e2ee: bool,
    signing_algo: SigningAlgo,
    ohttp: bool,
) -> Result<(), Box<dyn Error>> {
    let models: Vec<LiveModel> = serde_json::from_str(&required_env("NEARAI_E2E_MODELS")?)?;
    assert!(!models.is_empty(), "Expected representative Chat models");
    let selected: Vec<_> = if e2ee || ohttp {
        vec![models
            .iter()
            .find(|m| m.provider == "near")
            .ok_or_else(|| {
                io::Error::other("Expected a NEAR model for live encryption coverage")
            })?]
    } else {
        models.iter().collect()
    };
    for model in selected {
        println!(
            "integrated {}: {}, {signing_algo}, e2ee={e2ee}, ohttp={ohttp}",
            model.provider, model.id
        );
        tokio::time::timeout(
            Duration::from_secs(180),
            verify_chat(model, e2ee, signing_algo, ohttp),
        )
        .await??;
    }
    Ok(())
}

async fn verify_chat(
    model: &LiveModel,
    e2ee: bool,
    signing_algo: SigningAlgo,
    ohttp: bool,
) -> Result<(), Box<dyn Error>> {
    let client = InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(required_env("NEARAI_API_KEY")?),
        base_url: required_env("NEARAI_BASE_URL")?,
        e2ee,
        signing_algo,
        ohttp,
        ..Default::default()
    })?;
    // Cover explicit preflight as well as automatic preflight on the first Chat.
    let preflight = if e2ee {
        None
    } else {
        Some(client.verify(&model.id).await?)
    };
    for stream in [false, true] {
        if model.provider == "chutes" && stream {
            continue;
        }
        let body = json!({
            "model": model.id,
            "messages": [{"role": "user", "content": "Reply with the single word OK."}],
            "max_completion_tokens": 1024,
            "stream": stream,
        });
        let response = if stream {
            let response = client.send(client.chat_request(body)?).await?;
            assert!(
                response.status.is_success(),
                "Chat returned HTTP {}",
                response.status
            );
            // Consume HTTP EOF, including any bytes after SSE [DONE] and OHTTP's
            // authenticated final chunk, before looking up the retained receipt.
            response.bytes().await?
        } else {
            serde_json::to_vec(&client.chat_completions(body).await?)?
        };
        let id = read_completion_id(&response, stream)?;
        let receipt = verify_receipt_with_retry(&client, &id).await?;
        assert_eq!(receipt.signature.signer.signing_algo, signing_algo);
        if model.provider != "near" {
            assert_eq!(receipt.signature_kind(), CompletionSignatureKind::Gateway);
        }
        let cached_receipt = client.verify_response(&id).await?;
        assert_eq!(
            cached_receipt.signature.signature,
            receipt.signature.signature
        );

        let verified = client.verify(&model.id).await?;
        assert!(matches!(
            verified.gateway.tls_binding,
            GatewayTlsBinding::Attested { .. }
        ));
        if let Some(preflight) = &preflight {
            assert_eq!(verified.verified_at, preflight.verified_at);
        }
        assert_eq!(
            client.verify(&model.id).await?.verified_at,
            verified.verified_at
        );
        if model.provider == "near" {
            assert!(!verified.models.is_empty(), "Expected NEAR model evidence");
            for report in &verified.models {
                assert_eq!(report.gpu_evidence, GpuEvidenceStatus::Verified);
                assert!(report.signing_public_key.is_some());
            }
        } else {
            assert!(
                verified.models.is_empty(),
                "Expected Gateway-only verification"
            );
        }
        println!(
            "integrated {signing_algo}, e2ee={e2ee}, ohttp={ohttp}, stream={stream}: verified {:?} receipt",
            receipt.signature_kind()
        );
    }
    Ok(())
}

async fn verify_receipt_with_retry(
    client: &InferenceClient,
    id: &str,
) -> Result<VerifiedCompletionResult, InferenceError> {
    // Retry only receipt propagation. Never replay inference or retry a failed
    // cryptographic check; the integrated client classifies those as permanent.
    for backoff_ms in [500, 1_000, 2_000, 4_000] {
        match client.verify_response(id).await {
            Err(error) if error.retryable() => {
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
            result => return result,
        }
    }
    client.verify_response(id).await
}
