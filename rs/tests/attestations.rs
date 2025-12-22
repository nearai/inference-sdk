mod internal;

use crate::internal::context::init_context;
use internal::common::{
    fetch_attestation_report, fetch_domain_attestation, generate_request_nonce,
};
use verification_sdk::{
    verify_domain_attestation, verify_gateway_attestation, verify_model_attestation, SigningAlgo,
};

#[tokio::test]
async fn gateway_attestation_and_model_attestations_ecdsa() {
    test_gateway_attestation_and_model_attestations(SigningAlgo::Ecdsa).await;
}

#[tokio::test]
async fn gateway_attestation_and_model_attestations_ed25519() {
    test_gateway_attestation_and_model_attestations(SigningAlgo::Ed25519).await;
}

#[tokio::test]
async fn domain_attestation() {
    let ctx = init_context();
    let attestation = fetch_domain_attestation(&ctx.api_domain).await;
    verify_domain_attestation(&attestation).await.unwrap();
}

async fn test_gateway_attestation_and_model_attestations(signing_algo: SigningAlgo) {
    let ctx = init_context();
    let request_nonce = generate_request_nonce();

    let report = fetch_attestation_report(&ctx, &request_nonce, signing_algo).await;

    assert_eq!(report.gateway_attestation.request_nonce, request_nonce);
    assert_eq!(report.gateway_attestation.signing_algo, Some(signing_algo));

    verify_gateway_attestation(&report.gateway_attestation, &ctx.api_domain)
        .await
        .unwrap();

    for model_attestation in report.model_attestations.unwrap_or_default() {
        assert_eq!(model_attestation.request_nonce, request_nonce);
        assert_eq!(model_attestation.signing_algo, signing_algo);
        verify_model_attestation(&model_attestation).await.unwrap();
    }
}
