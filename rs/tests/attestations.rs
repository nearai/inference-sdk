mod internal;

use internal::common::{
    fetch_attestation_report, fetch_domain_attestation, generate_request_nonce,
};
use internal::context::init_context;
use verification_sdk::{
    verify_domain_attestation, verify_gateway_attestation, verify_model_attestation, SigningAlgo,
    VerifyDomainAttestationConfig, VerifyGatewayAttestationConfig, VerifyModelAttestationConfig,
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
    verify_domain_attestation(
        &attestation,
        &VerifyDomainAttestationConfig {
            image_names_of_sigstore_hash: vec!["nearaidev/dstack-ingress-vpc".to_owned()],
        },
    )
    .await
    .unwrap();
}

async fn test_gateway_attestation_and_model_attestations(signing_algo: SigningAlgo) {
    let ctx = init_context();
    let request_nonce = generate_request_nonce();

    let report = fetch_attestation_report(
        &ctx.api_url,
        &ctx.api_key,
        &ctx.model,
        &request_nonce,
        signing_algo,
    )
    .await;

    assert_eq!(report.gateway_attestation.request_nonce, request_nonce);
    assert_eq!(report.gateway_attestation.signing_algo, Some(signing_algo));

    verify_gateway_attestation(
        &report.gateway_attestation,
        &VerifyGatewayAttestationConfig {
            domain: ctx.api_domain.clone(),
            image_names_of_sigstore_hash: vec!["nearaidev/cloud-api".to_owned()],
        },
    )
    .await
    .unwrap();

    for model_attestation in report.model_attestations.unwrap_or_default() {
        assert_eq!(model_attestation.request_nonce, request_nonce);
        assert_eq!(model_attestation.signing_algo, signing_algo);
        verify_model_attestation(
            &model_attestation,
            &VerifyModelAttestationConfig {
                image_names_of_sigstore_hash: vec!["nearaidev/vllm-proxy".to_owned()],
            },
        )
        .await
        .unwrap();
    }
}
