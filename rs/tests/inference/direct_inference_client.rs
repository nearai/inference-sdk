use super::fixture::{body, setup, Fixture};
use async_trait::async_trait;
use nearai_inference_sdk::*;
use serde_json::Value;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct DeploymentCheck(Arc<AtomicUsize>);
#[async_trait]
impl DeploymentVerifier for DeploymentCheck {
    async fn verify(&self, _: &MeasuredDeployment) -> Result<(), VerificationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn direct_deployment_verifier_checks_every_report() {
    let (_server, _fixture, mut options) = setup(Fixture {
        direct: true,
        ..Default::default()
    })
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    options.model_verification.deployment = Some(Arc::new(DeploymentCheck(calls.clone())));
    let client = DirectInferenceClient::with_options(options.into()).unwrap();
    let verified = client.verify("vendor/model").await.unwrap();
    assert_eq!(verified.attestations.len(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    client.chat_completions(body()).await.unwrap();
    let receipt: VerifiedDirectCompletionResult = client.verify_response("chat-0").await.unwrap();
    assert_eq!(receipt.attestations.len(), 2);
    assert!(receipt.attestations.iter().all(|report| report
        .attestation
        .evidence
        .deployment_provenance
        == DeploymentProvenanceStatus::Verified));
}

#[tokio::test]
async fn direct_client_verifies_entire_report_set_and_default_signature_kind() {
    let (_server, f, options) = setup(Fixture {
        direct: true,
        ..Default::default()
    })
    .await;
    let client = DirectInferenceClient::with_options(DirectInferenceClientOptions {
        api_key: options.api_key,
        base_url: options.base_url,
        headers: options.headers,
        model_verification: options.model_verification,
        ..Default::default()
    })
    .unwrap();
    let verified = client.verify("vendor/model").await.unwrap();
    assert_eq!(verified.attestations.len(), 2);
    assert_eq!(verified.tls_binding, GatewayTlsBinding::None);
    client.chat_completions(body()).await.unwrap();
    let receipt = client.verify_response("chat-0").await.unwrap();
    assert_eq!(receipt.attestations.len(), 2);
    assert_eq!(receipt.id, "chat-0");
    assert_eq!(
        receipt.signature_kind(),
        CompletionSignatureKind::ProviderTee
    );
    assert_eq!(
        client
            .verify_response("chat-0")
            .await
            .unwrap()
            .attestations
            .len(),
        2
    );
    assert_eq!(f.signatures.load(Ordering::SeqCst), 1);
    assert_eq!(f.gateway.load(Ordering::SeqCst), 0);
    let receipts = f.receipts.lock().unwrap();
    let request: Value = serde_json::from_slice(&receipts["chat-0"].0).unwrap();
    assert_eq!(request["messages"][0]["content"], "Hello");
}

#[tokio::test]
async fn direct_rejects_invalid_nonserving_report_before_chat() {
    let (_server, f, options) = setup(Fixture {
        direct: true,
        bad_model: true,
        ..Default::default()
    })
    .await;
    let client = DirectInferenceClient::with_options(options.into()).unwrap();
    assert!(client.chat_completions(body()).await.is_err());
    assert_eq!(f.chat.load(Ordering::SeqCst), 0);
}
