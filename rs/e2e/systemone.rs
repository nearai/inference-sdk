use nearai_inference_sdk::{
    CompletionSignatureKind, InferenceClient, InferenceClientOptions, SigningAlgo, SystemOneAnswer,
};
use serde_json::json;
use std::{error::Error, time::Duration};

#[tokio::test]
#[ignore = "requires live Gateway credentials and NEARAI_E2E_SYSTEMONE_MODEL"]
async fn verified_systemone_decisions() -> Result<(), Box<dyn Error>> {
    for algo in [SigningAlgo::Ed25519, SigningAlgo::Ecdsa] {
        tokio::time::timeout(Duration::from_secs(180), async {
            let client = InferenceClient::with_options(InferenceClientOptions {
                api_key: Some(super::required_env("NEARAI_API_KEY")?),
                base_url: super::required_env("NEARAI_BASE_URL")?,
                signing_algo: algo,
                ..Default::default()
            })?;
            let request = json!({
                "model": super::required_env("NEARAI_E2E_SYSTEMONE_MODEL")?,
                "state": {"message":"I was charged twice for my subscription. Please help."},
                "questions": {
                    "billing":{"type":"noul","instructions":"Is this about billing?"},
                    "team":{"type":"choice","criteria":{"billing":"Payments","support":"Technical help"}},
                    "urgency":{"type":"score","criteria":["Routine","Prompt attention","Critical"]}
                }
            });
            let result = client.systemone_create(&request).await?;
            let mut receipt = client.verify_response(&result.decision_id).await;
            for delay in [500, 1_000, 2_000, 4_000] {
                if !receipt.as_ref().is_err_and(|e| e.retryable() || e.code() == "api.completion_signature_unavailable") { break; }
                tokio::time::sleep(Duration::from_millis(delay)).await;
                receipt = client.verify_response(&result.decision_id).await;
            }
            let receipt = receipt?;
            assert_eq!(receipt.signature_kind(), CompletionSignatureKind::Gateway);
            assert_eq!(receipt.signature.signer.signing_algo, algo);
            match receipt.attestation {
                nearai_inference_sdk::VerifiedCompletionAttestation::Gateway(attestation) => {
                    assert!(matches!(attestation.tls_binding, nearai_inference_sdk::GatewayTlsBinding::Attested { .. }));
                }
                _ => unreachable!(),
            }
            assert!(matches!(result.data.answers["billing"], SystemOneAnswer::Noul { .. }));
            assert!(matches!(result.data.answers["team"], SystemOneAnswer::Choice { .. }));
            assert!(matches!(result.data.answers["urgency"], SystemOneAnswer::Score { .. }));
            println!("{algo}: verified System One Gateway receipt");
            Ok::<_, Box<dyn Error>>(())
        }).await??;
    }
    Ok(())
}
