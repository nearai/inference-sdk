mod support;

use support::{gateway_attestation, model_quote, FixtureQuoteVerifier, NONCE, TLS_FINGERPRINT};
use verifiable_ai_sdk::{
    verify_gateway_attestation, AttestationPolicy, AttestationVerifiers, TcbStatus,
    VerificationError,
};

#[tokio::test]
async fn binds_the_observed_tls_peer() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = gateway_attestation();

    let verified = verify_gateway_attestation(
        &attestation,
        NONCE,
        TLS_FINGERPRINT,
        Some(&AttestationPolicy::default()),
        AttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(verified.tls_binding.spki_fingerprint, TLS_FINGERPRINT);
}

#[tokio::test]
async fn rejects_another_tls_peer() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = gateway_attestation();

    let error = verify_gateway_attestation(
        &attestation,
        NONCE,
        "44".repeat(32).as_str(),
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
async fn rejects_an_empty_declared_tls_fingerprint() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let mut attestation = gateway_attestation();
    attestation.evidence.declared_spki_fingerprint = Some(String::new());

    let error = verify_gateway_attestation(
        &attestation,
        NONCE,
        TLS_FINGERPRINT,
        None,
        AttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(error, VerificationError::SpkiFingerprintMissing));
}
