mod support;

use support::{
    model_attestation, model_quote, FixtureNvidiaVerifier, FixtureQuoteVerifier, NONCE,
    TLS_FINGERPRINT,
};
use verifiable_ai_sdk::{
    verify_model_attestation, DeploymentProvenanceStatus, GpuEvidenceRequirement,
    GpuEvidenceStatus, ModelAttestationPolicy, ModelAttestationVerifiers, ModelTlsBinding,
    TcbStatus, VerificationError,
};

#[tokio::test]
async fn accepts_missing_gpu_evidence() {
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::OutOfDate));
    let attestation = model_attestation(None, false);

    let verified = verify_model_attestation(
        &attestation,
        NONCE,
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
    assert_eq!(verified.tls_binding, ModelTlsBinding::None);
    assert_eq!(
        verified.evidence.deployment_provenance,
        DeploymentProvenanceStatus::NotChecked
    );
}

#[tokio::test]
async fn accepts_tls_bound_report_data() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = model_attestation(None, true);

    let verified = verify_model_attestation(
        &attestation,
        NONCE,
        None,
        ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        verified.tls_binding,
        ModelTlsBinding::Declared {
            spki_fingerprint: TLS_FINGERPRINT.to_owned(),
        }
    );
}

#[tokio::test]
async fn does_not_downgrade_declared_tls_to_legacy_binding() {
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::UpToDate));
    let mut attestation = model_attestation(None, true);
    attestation.reported_quote_data = None;

    let error = verify_model_attestation(
        &attestation,
        NONCE,
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
            binding: "signer_tls_binding"
        }
    ));
}

#[tokio::test]
async fn rejects_an_empty_gpu_payload() {
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::UpToDate));
    let attestation = model_attestation(Some(""), false);

    let error = verify_model_attestation(
        &attestation,
        NONCE,
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
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::UpToDate));
    let attestation = model_attestation(None, false);
    let policy = ModelAttestationPolicy {
        accepted_tcb_statuses: None,
        gpu_evidence: GpuEvidenceRequirement::Required,
    };

    let error = verify_model_attestation(
        &attestation,
        NONCE,
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
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::UpToDate));
    let nvidia = FixtureNvidiaVerifier;
    let payload = format!(r#"{{"nonce":"{NONCE}"}}"#);
    let attestation = model_attestation(Some(&payload), false);

    let verified = verify_model_attestation(
        &attestation,
        NONCE,
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
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::UpToDate));
    let mut attestation = model_attestation(None, false);
    attestation.reported_quote_data = Some("00".repeat(64));

    let error = verify_model_attestation(
        &attestation,
        NONCE,
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
    let mut quote = model_quote(false, TcbStatus::UpToDate);
    quote.rt_mr3[0] ^= 1;
    let quote = FixtureQuoteVerifier(quote);
    let attestation = model_attestation(None, false);
    let error = verify_model_attestation(
        &attestation,
        NONCE,
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
    let mut quote = model_quote(false, TcbStatus::UpToDate);
    quote.mr_config_id[1] ^= 1;
    let quote = FixtureQuoteVerifier(quote);
    let attestation = model_attestation(None, false);

    let error = verify_model_attestation(
        &attestation,
        NONCE,
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
