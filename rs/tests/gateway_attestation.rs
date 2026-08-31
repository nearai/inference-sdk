mod support;

use async_trait::async_trait;
use support::{
    gateway_attestation, model_quote, FixtureQuoteVerifier, APP_COMPOSE, NONCE, TLS_FINGERPRINT,
};
use verifiable_ai_sdk::{
    verify_gateway_attestation, AttestationVerifiers, DeploymentProvenanceStatus,
    DeploymentVerifier, GatewayAttestationPolicy, GatewayClientBinding, GatewayTlsBinding,
    MeasuredDeployment, TcbStatus, VerificationError,
};

fn client_binding(peer_spki_fingerprint: Option<String>) -> GatewayClientBinding {
    GatewayClientBinding {
        nonce: NONCE.to_owned(),
        peer_spki_fingerprint,
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

struct RejectingDeploymentVerifier;

#[async_trait]
impl DeploymentVerifier for RejectingDeploymentVerifier {
    async fn verify(&self, _deployment: &MeasuredDeployment) -> Result<(), VerificationError> {
        Err(VerificationError::DeploymentProvenanceRejected)
    }
}

#[tokio::test]
async fn binds_the_observed_tls_peer_by_default() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = gateway_attestation();

    let verified = verify_gateway_attestation(
        &attestation,
        &client_binding(Some(TLS_FINGERPRINT.to_owned())),
        None,
        AttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        verified.tls_binding,
        GatewayTlsBinding::Peer {
            spki_fingerprint: TLS_FINGERPRINT.to_owned(),
        }
    );
}

#[tokio::test]
async fn requires_an_observed_tls_peer_by_default() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = gateway_attestation();

    let error = verify_gateway_attestation(
        &attestation,
        &client_binding(None),
        None,
        AttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(error, VerificationError::PeerTlsBindingRequired));
    assert_eq!(error.code(), "policy.peer_tls_binding_required");
}

#[tokio::test]
async fn rejects_another_tls_peer() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = gateway_attestation();

    let error = verify_gateway_attestation(
        &attestation,
        &client_binding(Some("44".repeat(32))),
        None,
        AttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(error, VerificationError::SpkiFingerprintMismatch));
}

#[tokio::test]
async fn can_disable_peer_tls_binding_for_non_peer_runtimes() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = gateway_attestation();
    let policy = GatewayAttestationPolicy {
        verify_peer_tls_binding: false,
        ..Default::default()
    };

    let verified = verify_gateway_attestation(
        &attestation,
        &client_binding(None),
        Some(&policy),
        AttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        verified.tls_binding,
        GatewayTlsBinding::Attested {
            spki_fingerprint: TLS_FINGERPRINT.to_owned(),
        }
    );
}

#[tokio::test]
async fn rejects_an_invalid_declared_tls_fingerprint() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let mut attestation = gateway_attestation();
    attestation.declared_spki_fingerprint = String::new();

    let error = verify_gateway_attestation(
        &attestation,
        &client_binding(Some(TLS_FINGERPRINT.to_owned())),
        None,
        AttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(
        matches!(error, VerificationError::InvalidInput { ref field, .. } if field == "attestation.declared_spki_fingerprint")
    );
}

#[tokio::test]
async fn applies_an_explicit_gateway_tcb_policy() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = gateway_attestation();
    let policy = GatewayAttestationPolicy {
        accepted_tcb_statuses: Some(vec![TcbStatus::OutOfDate]),
        ..Default::default()
    };

    let error = verify_gateway_attestation(
        &attestation,
        &client_binding(Some(TLS_FINGERPRINT.to_owned())),
        Some(&policy),
        AttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::TcbStatusNotAllowed {
            actual: TcbStatus::UpToDate,
            accepted,
            ..
        } if accepted == vec![TcbStatus::OutOfDate]
    ));
}

#[tokio::test]
async fn runs_gateway_deployment_verifiers() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = gateway_attestation();
    let deployment = ExpectedDeploymentVerifier;

    let verified = verify_gateway_attestation(
        &attestation,
        &client_binding(Some(TLS_FINGERPRINT.to_owned())),
        None,
        AttestationVerifiers {
            quote: Some(&quote),
            deployment: Some(&deployment),
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
async fn propagates_a_rejected_gateway_deployment_verifier() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = gateway_attestation();
    let deployment = RejectingDeploymentVerifier;

    let error = verify_gateway_attestation(
        &attestation,
        &client_binding(Some(TLS_FINGERPRINT.to_owned())),
        None,
        AttestationVerifiers {
            quote: Some(&quote),
            deployment: Some(&deployment),
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::DeploymentProvenanceRejected
    ));
}
