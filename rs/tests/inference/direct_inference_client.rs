use super::fixture::{body, direct_options, setup, Fixture};
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

#[test]
fn direct_requires_explicit_endpoint() {
    let error = DirectInferenceClient::with_options(Default::default())
        .err()
        .expect("Direct requires a model endpoint URL");
    assert_eq!(error.code(), "api.invalid_input");
    let client = DirectInferenceClient::with_options(DirectInferenceClientOptions {
        base_url: "https://model.test/v1".into(),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(client.base_url(), "https://model.test/v1/");
}

#[tokio::test]
async fn direct_tls_verifies_every_report_and_the_serving_peer() {
    for case in ["valid", "wrong peer", "invalid sibling"] {
        let (_server, _, options) = setup(Fixture {
            direct: true,
            bad_model: case == "invalid sibling",
            ..Default::default()
        })
        .await;
        let api = DirectAttestationClient::new(&options.base_url, options.api_key.clone())
            .unwrap()
            .with_headers(options.headers);
        let mut fetched = api
            .fetch_model_attestations(Some(SigningAlgo::Ed25519), None)
            .await
            .unwrap();
        fetched.client_binding.spki_fingerprint =
            Some(if case == "wrong peer" { "33" } else { "11" }.repeat(32));
        let result = verify_direct_model_attestations(
            &fetched,
            None,
            ModelAttestationVerifiers {
                tdx_quote: options.model_verification.tdx_quote.as_deref(),
                ..Default::default()
            },
        )
        .await;
        match case {
            "valid" => {
                let verified = result.unwrap();
                assert_eq!(verified.attestations.len(), 2);
                assert_eq!(
                    verified.spki_fingerprints,
                    ["11".repeat(32), "22".repeat(32)]
                );
                assert!(matches!(
                    verified.tls_binding,
                    GatewayTlsBinding::Attested { .. }
                ));
            }
            "wrong peer" => assert_eq!(
                result.unwrap_err().code(),
                "binding.spki_fingerprint_mismatch"
            ),
            _ => assert_eq!(result.unwrap_err().code(), "binding.report_data_mismatch"),
        }
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
    let client = DirectInferenceClient::with_options(direct_options(options)).unwrap();
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
    let client = DirectInferenceClient::with_options(direct_options(options)).unwrap();
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
    let client = DirectInferenceClient::with_options(direct_options(options)).unwrap();
    assert!(client.chat_completions(body()).await.is_err());
    assert_eq!(f.chat.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn direct_receipt_uses_only_the_selected_signer_group() {
    for e2ee in [false, true] {
        for wrong_signer in [false, true] {
            let (_server, _, mut options) = setup(Fixture {
                direct: true,
                extra_model: true,
                wrong_signer,
                ..Default::default()
            })
            .await;
            options.e2ee = e2ee;
            let client = DirectInferenceClient::with_options(direct_options(options)).unwrap();
            let verified = client.verify("vendor/model").await.unwrap();
            assert_eq!(verified.attestations.len(), 3);
            client.chat_completions(body()).await.unwrap();
            let receipt = client.verify_response("chat-0").await;
            if wrong_signer {
                assert_eq!(receipt.unwrap_err().code(), "signature.signer_mismatch");
            } else {
                let attestations = receipt.unwrap().attestations;
                assert_eq!(attestations.len(), 2);
                assert_eq!(attestations[0].instance_id.as_deref(), Some("serving"));
                assert_eq!(attestations[1].instance_id.as_deref(), Some("other"));
            }
        }
    }
}
