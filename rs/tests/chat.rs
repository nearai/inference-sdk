mod internal;

use internal::common::{
    chat_completions, fetch_attestation_report, fetch_chat_signature, generate_request_nonce, sleep,
};
use internal::context::init_context;
use serde_json::json;
use verification_sdk::{verify_chat, verify_signing_address, Chat, SigningAlgo};

#[tokio::test]
async fn chat_signature_ecdsa() {
    test_chat_signature(SigningAlgo::Ecdsa).await;
}

#[tokio::test]
async fn chat_signature_ed25519() {
    test_chat_signature(SigningAlgo::Ed25519).await;
}

async fn test_chat_signature(signing_algo: SigningAlgo) {
    let ctx = init_context();

    let completions = chat_completions(
        &ctx.api_url,
        &ctx.api_key,
        &json!({
            "model": ctx.model,
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": true
        }),
    )
    .await;

    sleep(5_000).await; // Waiting for signature preparation

    let signature = fetch_chat_signature(
        &ctx.api_url,
        &ctx.api_key,
        &ctx.model,
        &completions.id,
        signing_algo,
    )
    .await;
    assert_eq!(signature.signing_algo, signing_algo);

    let chat = Chat {
        request_body: completions.request_body_raw.clone(),
        response_body: completions.response_body_raw.clone(),
    };

    verify_chat(&chat, &signature).unwrap();

    let report = fetch_attestation_report(
        &ctx.api_url,
        &ctx.api_key,
        &ctx.model,
        &generate_request_nonce(),
        signing_algo,
    )
    .await;
    let attestations = report.model_attestations.unwrap_or_default();
    verify_signing_address(&signature, &attestations).unwrap();
}
