use base64::{engine::general_purpose::STANDARD, Engine};
use nearai_inference_sdk::{
    verify_image_provenance, ImageProvenanceFailureReason as Reason, ImageProvenancePolicy,
    VerificationError,
};
use serde_json::Value;

const BUNDLE: &str =
    include_str!("../../test-fixtures/provenance/compose-manager-launcher.bundle.json");
const DIGEST: &str = "sha256:91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56";
const COMMIT: &str = "8e07c3583909c9ab9da94d883e87add1ae90832d";
const REUSABLE_BUNDLE: &str =
    include_str!("../../test-fixtures/provenance/reusable-workflow.bundle.json");
const REUSABLE_DIGEST: &str =
    "sha256:49a3aa6075e0f49f82843e74b5baa614ad2a588e6675612bf108a0a008c5ac25";
const SOURCE_COMMIT: &str = "95baf27389e83e6a5c48f42e190d48d7abcea19e";
const SIGNER_IDENTITY: &str = "https://github.com/github/artifact-attestations-workflows/.github/workflows/attest.yml@09b495c3f12c7881b3cc17209a327792065c1a1d";

fn policy() -> ImageProvenancePolicy {
    ImageProvenancePolicy::new(
        "nearai/compose-manager".to_owned(),
        ".github/workflows/build.yml".to_owned(),
    )
}

fn reusable_policy() -> ImageProvenancePolicy {
    let mut policy = ImageProvenancePolicy::new(
        "malancas/attest-demo".to_owned(),
        ".github/workflows/shared.yml".to_owned(),
    );
    policy.git_ref = Some("refs/heads/main".to_owned());
    policy.commit = Some(SOURCE_COMMIT.to_owned());
    policy.signer_identity = Some(SIGNER_IDENTITY.to_owned());
    policy
}

#[tokio::test]
async fn verifies_a_real_cross_repository_reusable_workflow_and_returns_source_identity() {
    let policy = reusable_policy();
    let verified = verify_image_provenance(&[REUSABLE_BUNDLE.to_owned()], REUSABLE_DIGEST, &policy)
        .await
        .unwrap();

    assert_eq!(verified.repository, policy.repository);
    assert_eq!(verified.workflow, policy.workflow);
    assert_eq!(verified.git_ref, "refs/heads/main");
    assert_eq!(verified.commit, SOURCE_COMMIT);
    assert_eq!(verified.certificate_identity, SIGNER_IDENTITY);
    assert_eq!(verified.digest, REUSABLE_DIGEST);
}

#[tokio::test]
async fn requires_the_reusable_signer_and_independent_source_policy() {
    let mut missing_signer = reusable_policy();
    missing_signer.signer_identity = None;
    let mut wrong_signer = reusable_policy();
    wrong_signer.signer_identity = Some(format!("{SIGNER_IDENTITY}-wrong"));
    let mut wrong_repository = reusable_policy();
    wrong_repository.repository = "another/source".to_owned();
    let mut wrong_workflow = reusable_policy();
    wrong_workflow.workflow = ".github/workflows/other.yml".to_owned();
    let mut wrong_ref = reusable_policy();
    wrong_ref.git_ref = Some("refs/heads/other".to_owned());
    let mut wrong_commit = reusable_policy();
    wrong_commit.commit = Some("a".repeat(40));
    for (policy, expected) in [
        (missing_signer, Reason::UntrustedIdentity),
        (wrong_signer, Reason::UntrustedIdentity),
        (wrong_repository, Reason::SourceMismatch),
        (wrong_workflow, Reason::SourceMismatch),
        (wrong_ref, Reason::SourceMismatch),
        (wrong_commit, Reason::CommitMismatch),
    ] {
        let error =
            verify_image_provenance(&[REUSABLE_BUNDLE.to_owned()], REUSABLE_DIGEST, &policy)
                .await
                .unwrap_err();
        assert!(matches!(
            error,
            VerificationError::ImageProvenanceVerificationFailed { reasons, .. }
                if reasons == vec![expected]
        ));
    }
}

fn tampered_bundle() -> String {
    let mut bundle: Value = serde_json::from_str(BUNDLE).unwrap();
    let payload = bundle["dsseEnvelope"]["payload"].as_str().unwrap();
    let decoded = STANDARD.decode(payload).unwrap();
    let mut statement: Value = serde_json::from_slice(&decoded).unwrap();
    statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] =
        Value::String("a".repeat(40));
    bundle["dsseEnvelope"]["payload"] = Value::String(STANDARD.encode(statement.to_string()));
    bundle.to_string()
}

#[tokio::test]
async fn verifies_real_github_build_provenance_and_optional_pins() {
    let mut policy = policy();
    policy.git_ref = Some("refs/heads/master".to_owned());
    policy.commit = Some(COMMIT.to_owned());
    let bundles = vec![BUNDLE.to_owned()];

    let verified = verify_image_provenance(&bundles, DIGEST, &policy)
        .await
        .unwrap();

    assert_eq!(verified.digest, DIGEST);
    assert_eq!(verified.repository, policy.repository);
    assert_eq!(verified.workflow, policy.workflow);
    assert_eq!(verified.commit, COMMIT);
    assert_eq!(verified.git_ref, "refs/heads/master");
    assert_eq!(verified.predicate_type, "https://slsa.dev/provenance/v1");
    assert_eq!(verified.issuer, policy.issuer);
    assert_eq!(
        verified.certificate_identity,
        "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master"
    );
}

#[tokio::test]
async fn rejects_a_payload_changed_after_signing() {
    let bundles = vec![tampered_bundle()];
    let error = verify_image_provenance(&bundles, DIGEST, &policy())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::ImageProvenanceVerificationFailed { reasons, .. }
            if reasons == vec![Reason::InvalidBundle]
    ));
}

#[tokio::test]
async fn rejects_a_bundle_for_a_different_image_digest() {
    let bundles = vec![BUNDLE.to_owned()];
    let different_digest = format!("sha256:{}", "00".repeat(32));
    let error = verify_image_provenance(&bundles, &different_digest, &policy())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::ImageProvenanceVerificationFailed { reasons, .. }
            if reasons == vec![Reason::DigestMismatch]
    ));
}

#[tokio::test]
async fn rejects_tampered_transparency_log_evidence() {
    let mut bundle: Value = serde_json::from_str(BUNDLE).unwrap();
    bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["rootHash"] =
        Value::String(STANDARD.encode([0; 32]));
    let bundles = vec![bundle.to_string()];
    let error = verify_image_provenance(&bundles, DIGEST, &policy())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::ImageProvenanceVerificationFailed { reasons, .. }
            if reasons == vec![Reason::InvalidBundle]
    ));
}

#[tokio::test]
async fn requires_the_configured_repository_workflow_ref_and_issuer() {
    let bundles = vec![BUNDLE.to_owned()];
    let mut wrong_repository = policy();
    wrong_repository.repository = "someone/compose-manager".to_owned();
    let mut wrong_workflow = policy();
    wrong_workflow.workflow = ".github/workflows/release.yml".to_owned();
    let mut wrong_ref = policy();
    wrong_ref.git_ref = Some("refs/heads/feature".to_owned());
    let mut wrong_issuer = policy();
    wrong_issuer.issuer = "https://example.com".to_owned();

    for rejected in [wrong_repository, wrong_workflow, wrong_ref, wrong_issuer] {
        let error = verify_image_provenance(&bundles, DIGEST, &rejected)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            VerificationError::ImageProvenanceVerificationFailed { reasons, .. }
                if reasons == vec![Reason::UntrustedIdentity]
        ));
    }
}

#[tokio::test]
async fn rejects_an_unapproved_source_commit() {
    let bundles = vec![BUNDLE.to_owned()];
    let mut policy = policy();
    policy.commit = Some("a".repeat(40));
    let error = verify_image_provenance(&bundles, DIGEST, &policy)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::ImageProvenanceVerificationFailed { reasons, .. }
            if reasons == vec![Reason::CommitMismatch]
    ));
}

#[tokio::test]
async fn accepts_a_later_valid_bundle_instead_of_stopping_at_the_first_failure() {
    let bundles = vec![tampered_bundle(), BUNDLE.to_owned()];
    let verified = verify_image_provenance(&bundles, DIGEST, &policy())
        .await
        .unwrap();

    assert_eq!(verified.commit, COMMIT);
}

#[tokio::test]
async fn reports_distinct_failure_reasons_when_no_candidate_verifies() {
    let bundles = vec![tampered_bundle(), "{}".to_owned(), BUNDLE.to_owned()];
    let mut policy = policy();
    policy.commit = Some("a".repeat(40));
    let error = verify_image_provenance(&bundles, DIGEST, &policy)
        .await
        .unwrap_err();

    assert_eq!(error.code(), "provenance.image_verification_failed");
    assert!(!error.retryable());
    assert!(matches!(
        error,
        VerificationError::ImageProvenanceVerificationFailed { reasons, .. }
            if reasons == vec![Reason::InvalidBundle, Reason::CommitMismatch]
    ));
}

#[tokio::test]
async fn rejects_a_collection_without_any_attestations() {
    let error = verify_image_provenance(&[], DIGEST, &policy())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::ImageProvenanceVerificationFailed { reasons, .. }
            if reasons == vec![Reason::NoAttestations]
    ));
}
