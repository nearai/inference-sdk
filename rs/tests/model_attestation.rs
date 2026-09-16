mod support;

use async_trait::async_trait;
use nearai_inference_sdk::{
    verify_model_attestation, DeploymentProvenanceStatus, DeploymentVerifier,
    GpuEvidenceRequirement, GpuEvidenceStatus, MeasuredDeployment, ModelAttestationPolicy,
    ModelAttestationVerifiers, ModelClientBinding, TcbStatus, VerificationError,
};
use support::{
    gateway_tls_quote, model_attestation, model_quote, FixtureNvidiaVerifier, FixtureQuoteVerifier,
    APP_COMPOSE, NONCE,
};

fn client_binding() -> ModelClientBinding {
    ModelClientBinding {
        nonce: NONCE.to_owned(),
    }
}

struct ExpectedDeploymentVerifier;

#[async_trait]
impl DeploymentVerifier for ExpectedDeploymentVerifier {
    async fn verify(&self, deployment: &MeasuredDeployment) -> Result<(), VerificationError> {
        if deployment.app_compose == APP_COMPOSE {
            Ok(())
        } else {
            Err(VerificationError::DeploymentProvenanceRejected)
        }
    }
}

#[tokio::test]
async fn accepts_missing_gpu_evidence() {
    let quote = FixtureQuoteVerifier(model_quote(TcbStatus::OutOfDate));
    let attestation = model_attestation(None);
    let client_binding = client_binding();

    let verified = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(verified.evidence.tcb_status, TcbStatus::OutOfDate);
    assert_eq!(verified.gpu_evidence, GpuEvidenceStatus::NotProvided);
    assert_eq!(
        verified.evidence.deployment_provenance,
        DeploymentProvenanceStatus::NotChecked
    );
}

#[tokio::test]
async fn runs_a_model_deployment_verifier() {
    let quote = FixtureQuoteVerifier(model_quote(TcbStatus::UpToDate));
    let attestation = model_attestation(None);
    let client_binding = client_binding();
    let deployment = ExpectedDeploymentVerifier;

    let verified = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            quote: Some(&quote),
            deployment: Some(&deployment),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        verified.evidence.deployment_provenance,
        DeploymentProvenanceStatus::Verified
    );
}

#[tokio::test]
async fn applies_an_explicit_model_tcb_policy() {
    let quote = FixtureQuoteVerifier(model_quote(TcbStatus::OutOfDate));
    let attestation = model_attestation(None);
    let client_binding = client_binding();
    let policy = ModelAttestationPolicy {
        accepted_tcb_statuses: Some(vec![TcbStatus::UpToDate]),
        ..Default::default()
    };

    let error = verify_model_attestation(
        &attestation,
        &client_binding,
        Some(&policy),
        ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::TcbStatusNotAllowed {
            actual: TcbStatus::OutOfDate,
            accepted,
            ..
        } if accepted == vec![TcbStatus::UpToDate]
    ));
}

#[tokio::test]
async fn rejects_tls_bound_report_data_for_cloud_model_evidence() {
    let quote = FixtureQuoteVerifier(gateway_tls_quote(TcbStatus::UpToDate));
    let mut attestation = model_attestation(None);
    let client_binding = client_binding();
    attestation.reported_quote_data = None;

    let error = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::ReportDataMismatch {
            binding: "signer_binding"
        }
    ));
}

#[tokio::test]
async fn rejects_an_empty_gpu_payload() {
    let quote = FixtureQuoteVerifier(model_quote(TcbStatus::UpToDate));
    let attestation = model_attestation(Some(""));
    let client_binding = client_binding();

    let error = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::GpuPayloadInvalid {
            reason: "invalid_json"
        }
    ));
}

#[tokio::test]
async fn enforces_required_gpu_policy() {
    let quote = FixtureQuoteVerifier(model_quote(TcbStatus::UpToDate));
    let attestation = model_attestation(None);
    let client_binding = client_binding();
    let policy = ModelAttestationPolicy {
        accepted_tcb_statuses: None,
        gpu_evidence: GpuEvidenceRequirement::Required,
    };

    let error = verify_model_attestation(
        &attestation,
        &client_binding,
        Some(&policy),
        ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(error, VerificationError::GpuEvidenceRequired));
}

#[tokio::test]
async fn verifies_supplied_gpu_evidence_with_a_custom_verifier() {
    let quote = FixtureQuoteVerifier(model_quote(TcbStatus::UpToDate));
    let nvidia = FixtureNvidiaVerifier;
    let payload = format!(r#"{{"nonce":"{NONCE}"}}"#);
    let attestation = model_attestation(Some(&payload));
    let client_binding = client_binding();

    let verified = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            quote: Some(&quote),
            nvidia: Some(&nvidia),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(verified.gpu_evidence, GpuEvidenceStatus::Verified);
}

#[tokio::test]
async fn rejects_incoherent_advertised_report_data() {
    let quote = FixtureQuoteVerifier(model_quote(TcbStatus::UpToDate));
    let mut attestation = model_attestation(None);
    let client_binding = client_binding();
    attestation.reported_quote_data = Some("00".repeat(64));

    let error = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        VerificationError::ReportDataMismatch {
            binding: "reported_quote_data"
        }
    ));
}

#[tokio::test]
async fn rejects_replayed_rtmr3_measurements() {
    let mut quote = model_quote(TcbStatus::UpToDate);
    quote.rt_mr3[0] ^= 1;
    let quote = FixtureQuoteVerifier(quote);
    let attestation = model_attestation(None);
    let client_binding = client_binding();
    let error = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        VerificationError::Rtmr3Mismatch {
            reason: "replay_mismatch"
        }
    ));
}

#[tokio::test]
async fn rejects_an_app_compose_not_bound_by_mrconfigid() {
    let mut quote = model_quote(TcbStatus::UpToDate);
    quote.mr_config_id[1] ^= 1;
    let quote = FixtureQuoteVerifier(quote);
    let attestation = model_attestation(None);
    let client_binding = client_binding();

    let error = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::AppComposeMrConfigIdMismatch
    ));
}
