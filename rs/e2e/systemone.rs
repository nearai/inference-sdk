use nearai_inference_sdk::{
    CompletionSignatureKind, InferenceClient, InferenceClientOptions, SigningAlgo, SystemOneAnswer,
};
use serde_json::json;
use std::{error::Error, time::Duration};

#[tokio::test]
#[ignore = "requires NEARAI_BASE_URL, NEARAI_API_KEY and NEARAI_E2E_MODELS"]
async fn verified_systemone_decisions() -> Result<(), Box<dyn Error>> {
    let models = super::select_models(&super::required_env("NEARAI_E2E_MODELS")?, "systemone")?;

    for algo in [SigningAlgo::Ed25519, SigningAlgo::Ecdsa] {
        tokio::time::timeout(Duration::from_secs(180), async {
            let client = InferenceClient::with_options(InferenceClientOptions {
                api_key: Some(super::required_env("NEARAI_API_KEY")?),
                base_url: super::required_env("NEARAI_BASE_URL")?,
                signing_algo: algo,
                ..Default::default()
            })?;

            let request = systemone_request(&models[0].id);

            let result = client.systemone_create(&request).await?;

            let mut receipt = client.verify_response(&result.decision_id).await;
            for delay in [500, 1_000, 2_000, 4_000] {
                if !receipt.as_ref().is_err_and(|e| {
                    e.retryable() || e.code() == "api.completion_signature_unavailable"
                }) {
                    break;
                }

                tokio::time::sleep(Duration::from_millis(delay)).await;
                receipt = client.verify_response(&result.decision_id).await;
            }

            let receipt = receipt?;

            assert_eq!(receipt.id, result.decision_id);
            assert!(!result.data.model.is_empty());
            assert!(result.data.usage.input_tokens > 0);
            if let SystemOneAnswer::Choice { choice, .. } = &result.data.answers["team"] {
                assert!(["billing", "support"].contains(&choice.as_str()));
            }
            assert_eq!(receipt.signature_kind(), CompletionSignatureKind::Gateway);
            assert_eq!(receipt.signature.signer.signing_algo, algo);
            match receipt.attestation {
                nearai_inference_sdk::VerifiedCompletionAttestation::Gateway(attestation) => {
                    assert!(matches!(
                        attestation.tls_binding,
                        nearai_inference_sdk::GatewayTlsBinding::Attested { .. }
                    ));
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                result.data.answers["billing"],
                SystemOneAnswer::Noul { .. }
            ));
            assert!(matches!(
                result.data.answers["team"],
                SystemOneAnswer::Choice { .. }
            ));
            assert!(matches!(
                result.data.answers["urgency"],
                SystemOneAnswer::Score { .. }
            ));

            println!("{algo}: verified System One Gateway receipt");
            Ok::<_, Box<dyn Error>>(())
        })
        .await??;
    }

    Ok(())
}

fn systemone_request(model: &str) -> serde_json::Value {
    json!({
        "model": model,
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
                "criteria": ["Routine", "Needs prompt attention", "Critical"]
            }
        }
    })
}

#[tokio::test]
#[ignore = "requires NEARAI_BASE_URL, NEARAI_API_KEY and NEARAI_E2E_MODELS"]
async fn standalone_systemone_binds_exact_bytes() -> Result<(), Box<dyn Error>> {
    use nearai_inference_sdk::{
        create_pinned_tls_client, verify_gateway_attestation, verify_gateway_response,
        AttestationClient, GatewayAttestationFetchOptions, GatewayTlsBinding,
    };
    tokio::time::timeout(Duration::from_secs(180), async {
        let base = super::required_env("NEARAI_BASE_URL")?;
        let key = super::required_env("NEARAI_API_KEY")?;
        let client = AttestationClient::with_base_url(key.clone(), &base)?;
        let fetched = client
            .fetch_gateway_attestation(GatewayAttestationFetchOptions {
                signing_algo: Some(SigningAlgo::Ed25519),
                ..Default::default()
            })
            .await?;
        let gateway = verify_gateway_attestation(
            &fetched.attestation,
            &fetched.client_binding,
            None,
            Default::default(),
        )
        .await?;
        let GatewayTlsBinding::Attested { spki_fingerprint } = &gateway.tls_binding else {
            return Err("missing attested TLS binding".into());
        };
        let http = create_pinned_tls_client(std::slice::from_ref(spki_fingerprint))?;
        let models = super::select_models(&super::required_env("NEARAI_E2E_MODELS")?, "systemone")?;
        let body = serde_json::to_vec(&systemone_request(&models[0].id))?;
        let response = http
            .post(format!("{}/systemone", base.trim_end_matches('/')))
            .bearer_auth(key)
            .header("content-type", "application/json")
            .header("accept-encoding", "identity")
            .header("x-no-aliasing", "true")
            .body(body.clone())
            .send()
            .await?;
        assert!(response.status().is_success());
        let id = response
            .headers()
            .get("x-generation-id")
            .ok_or("missing decision ID")?
            .to_str()?
            .to_owned();
        let raw = response.bytes().await?;
        let signature =
            super::fetch_signature_with_retry(&client, &id, SigningAlgo::Ed25519).await?;
        assert_eq!(signature.kind, CompletionSignatureKind::Gateway);
        verify_gateway_response(&body, &raw, &signature, &gateway)?;
        let mut altered_body = body.clone();
        altered_body.push(b' ');
        let mut altered_raw = raw.to_vec();
        altered_raw.push(b' ');
        assert!(verify_gateway_response(&altered_body, &raw, &signature, &gateway).is_err());
        assert!(verify_gateway_response(&body, &altered_raw, &signature, &gateway).is_err());
        Ok::<_, Box<dyn Error>>(())
    })
    .await?
}
