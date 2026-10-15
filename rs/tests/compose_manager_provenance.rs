mod support;

use async_trait::async_trait;
use nearai_inference_sdk::{
    verify_compose_manager_deployment_image_provenance, verify_model_attestation,
    ComposeManagerAttestation, ModelAttestationVerifiers, ModelClientBinding, TcbStatus,
    TdxQuoteVerificationResult, TdxQuoteVerifier, VerificationError,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use support::{model_attestation, model_quote, NONCE};

const FIXTURE: &str = include_str!("../../test-fixtures/compose-manager/deployment.json");

fn manager_report() -> ComposeManagerAttestation {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    serde_json::from_value(json!({
        "actions": fixture["actions"], "actions_hash": fixture["actions_hash"],
        "nonce": NONCE, "quote": "bb", "event_log": [{"imr": 3, "digest": "00".repeat(48)}],
    }))
    .unwrap()
}

struct QuoteVerifier;

#[async_trait]
impl TdxQuoteVerifier for QuoteVerifier {
    async fn verify(
        &self,
        intel_quote: &str,
    ) -> Result<TdxQuoteVerificationResult, VerificationError> {
        let mut quote = model_quote(TcbStatus::UpToDate);
        if intel_quote == "bb" {
            let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
            quote.report_data = hex::decode(format!(
                "{}{NONCE}",
                fixture["actions_hash"].as_str().unwrap()
            ))
            .unwrap();
        }
        Ok(quote)
    }
}

#[tokio::test]
async fn authenticates_the_shared_canonical_log_in_model_verification() {
    let mut attestation = model_attestation(None);
    attestation.compose_manager_attestation = Some(manager_report());
    let verified = verify_model_attestation(
        &attestation,
        &ModelClientBinding {
            nonce: NONCE.to_owned(),
        },
        None,
        ModelAttestationVerifiers {
            tdx_quote: Some(&QuoteVerifier),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let manager = verified.evidence.deployment.compose_manager.unwrap();
    assert_eq!(manager.actions, manager_report().actions);
    assert_eq!(manager.tcb_status, TcbStatus::UpToDate);
}

#[tokio::test]
async fn rejects_changed_actions_and_replayed_manager_evidence() {
    let mut changed = manager_report();
    changed.actions[0].file = Some("other.yaml".to_owned());
    let mut replayed = manager_report();
    replayed.nonce = "ff".repeat(32);
    for (report, code) in [
        (changed, "binding.compose_manager_actions_mismatch"),
        (replayed, "binding.nonce_mismatch"),
    ] {
        let mut attestation = model_attestation(None);
        attestation.compose_manager_attestation = Some(report);
        let error = verify_model_attestation(
            &attestation,
            &ModelClientBinding {
                nonce: NONCE.to_owned(),
            },
            None,
            ModelAttestationVerifiers {
                tdx_quote: Some(&QuoteVerifier),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), code);
    }
}

#[tokio::test]
async fn requires_manager_evidence_when_its_image_policy_is_selected() {
    let attestation = model_attestation(None);
    let verified = verify_model_attestation(
        &attestation,
        &ModelClientBinding {
            nonce: NONCE.to_owned(),
        },
        None,
        ModelAttestationVerifiers {
            tdx_quote: Some(&QuoteVerifier),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let error = verify_compose_manager_deployment_image_provenance(
        &verified.evidence.deployment,
        &BTreeMap::from([(
            "example/app".into(),
            nearai_inference_sdk::ImageProvenancePolicy::new(
                "nearai/compose-manager".into(),
                ".github/workflows/build.yml".into(),
            ),
        )]),
        &nearai_inference_sdk::ComposeManagerImagePolicy {
            image_repository: "nearaidev/compose-manager".into(),
            build: nearai_inference_sdk::ImageProvenancePolicy::new(
                "nearai/compose-manager".into(),
                ".github/workflows/build.yml".into(),
            ),
            signer_identity: None,
        },
        Default::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        VerificationError::ComposeManagerDeploymentInvalid {
            reason: "attestation_missing"
        }
    ));
}

fn image_policy() -> nearai_inference_sdk::ImageProvenancePolicy {
    nearai_inference_sdk::ImageProvenancePolicy::new(
        "nearai/compose-manager".into(),
        ".github/workflows/build.yml".into(),
    )
}
fn manager_image_policy() -> nearai_inference_sdk::ComposeManagerImagePolicy {
    nearai_inference_sdk::ComposeManagerImagePolicy {
        image_repository: "nearaidev/compose-manager-launcher".into(),
        build: image_policy(),
        signer_identity: None,
    }
}
fn deployment() -> nearai_inference_sdk::MeasuredDeployment {
    nearai_inference_sdk::MeasuredDeployment {
        app_compose: "{}".into(),
        runtime_measurements: Default::default(),
        compose_manager: Some(nearai_inference_sdk::VerifiedComposeManagerAttestation {
            actions: manager_report().actions,
            tcb_status: TcbStatus::UpToDate,
            advisory_ids: vec![],
            runtime_measurements: Default::default(),
        }),
    }
}

#[tokio::test]
async fn independently_verifies_current_manager_and_proxy_requests() {
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };
    let server = MockServer::start().await;
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    Mock::given(method("GET"))
        .and(path(
            "/proxy/repos/nearai/cvm-compose-files/contents/prod/model.yaml",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(fixture["compose"].as_str().unwrap()),
        )
        .mount(&server)
        .await;
    let bundle: Value = serde_json::from_str(include_str!(
        "../../test-fixtures/provenance/compose-manager-launcher.bundle.json"
    ))
    .unwrap();
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(
            "/proxy/repos/nearai/compose-manager/attestations/.*",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"attestations":[{"bundle":bundle}]})),
        )
        .mount(&server)
        .await;
    let proxy = format!("{}/proxy", server.uri());
    let policies = BTreeMap::from([("nearaidev/compose-manager-launcher".into(), image_policy())]);
    let options = nearai_inference_sdk::ComposeManagerDeploymentImageProvenanceOptions {
        github_proxy_url: Some(&proxy),
        github_token: Some("do-not-forward"),
        ..Default::default()
    };
    verify_compose_manager_deployment_image_provenance(
        &deployment(),
        &policies,
        &manager_image_policy(),
        options.clone(),
    )
    .await
    .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests
        .iter()
        .all(|r| !r.headers.contains_key("authorization")));
    assert_eq!(
        requests[0]
            .url
            .query_pairs()
            .find(|(k, _)| k == "ref")
            .unwrap()
            .1,
        "12".repeat(20)
    );
    nearai_inference_sdk::verify_deployment_image_provenance_with_options(
        &json!({"docker_compose_file": fixture["compose"]}).to_string(),
        &policies,
        nearai_inference_sdk::DeploymentImageProvenanceOptions {
            github_proxy_url: Some(&proxy),
            github_token: Some("do-not-forward"),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests
        .iter()
        .all(|r| !r.headers.contains_key("authorization")));
    let mut stale = deployment();
    stale.compose_manager.as_mut().unwrap().actions[1].image = Some(format!(
        "nearaidev/compose-manager-launcher@sha256:{}",
        "bb".repeat(32)
    ));
    let error = verify_compose_manager_deployment_image_provenance(
        &stale,
        &policies,
        &manager_image_policy(),
        options.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), "provenance.image_verification_failed");
    let mut missing = deployment();
    missing.compose_manager.as_mut().unwrap().actions[0].services = Some(vec!["missing".into()]);
    let error = verify_compose_manager_deployment_image_provenance(
        &missing,
        &policies,
        &manager_image_policy(),
        options,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        VerificationError::DeploymentImagesInvalid {
            reason: nearai_inference_sdk::DeploymentImagesFailureReason::ServiceMissing,
            ..
        }
    ));
}

#[tokio::test]
async fn empty_policy_and_missing_or_unlisted_manager_fail_before_network() {
    let policies = BTreeMap::from([("nearaidev/compose-manager-launcher".into(), image_policy())]);
    let error = verify_compose_manager_deployment_image_provenance(
        &deployment(),
        &BTreeMap::new(),
        &manager_image_policy(),
        Default::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        VerificationError::DeploymentImagesInvalid {
            reason: nearai_inference_sdk::DeploymentImagesFailureReason::EmptyPolicy,
            ..
        }
    ));
    for image in [
        None,
        Some(format!("other/manager@sha256:{}", "bb".repeat(32))),
    ] {
        let mut d = deployment();
        d.compose_manager.as_mut().unwrap().actions[1].image = image;
        let error = verify_compose_manager_deployment_image_provenance(
            &d,
            &policies,
            &manager_image_policy(),
            Default::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            VerificationError::ComposeManagerDeploymentInvalid { .. }
        ));
    }
}

#[tokio::test]
async fn direct_decoder_never_promotes_nested_manager_evidence() {
    use wiremock::{matchers::method, Mock, MockServer, Request, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(|request:&Request| {
        let nonce=request.url.query_pairs().find(|(key,_)|key=="nonce").unwrap().1.into_owned();
        let fixture:Value=serde_json::from_str(FIXTURE).unwrap();
        let mut report=json!({"model_name":"test","request_nonce":nonce,"signing_algo":"ed25519","signing_address":"aa".repeat(32),"intel_quote":"bb","event_log":[],"info":{"tcb_info":{"app_compose":"{}"}}});
        let mut nested=report.clone();nested["compose_manager_attestation"]=json!({"actions":fixture["actions"],"actions_hash":fixture["actions_hash"],"nonce":nonce,"quote":"cc","event_log":[]});report["all_attestations"]=json!([nested]);
        ResponseTemplate::new(200).set_body_json(report)
    }).mount(&server).await;
    let client = nearai_inference_sdk::DirectAttestationClient::new(&server.uri(), None).unwrap();
    let result = client.fetch_model_attestations(None, None).await.unwrap();
    assert!(result
        .serving_attestation
        .attestation
        .compose_manager_attestation
        .is_none());
    assert!(result.attestations[0]
        .attestation
        .compose_manager_attestation
        .is_none());
}
