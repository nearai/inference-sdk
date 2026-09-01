use serde_json::json;
use std::sync::Once;
use verifiable_ai_sdk::{
    find_model_attestation_for_signature, ApiError, AttestationClient, AttestationEventLog,
    AttestationEvidence, CompletionSignature, CompletionSignatureKind, CompletionSignatureLookup,
    GatewayAttestationPolicy, ModelAttestation, SdkError, SignatureUnavailable, SigningAlgo,
    SigningIdentity, VerificationError,
};
use wiremock::{
    matchers::{header, method, path, query_param, query_param_is_missing},
    Mock, MockServer, Request, Respond, ResponseTemplate,
};

#[derive(Clone)]
struct ModelAttestationResponder;

impl Respond for ModelAttestationResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let nonce = request
            .url
            .query_pairs()
            .find(|(key, _)| key == "nonce")
            .map(|(_, value)| value.into_owned())
            .expect("request contains a nonce");
        ResponseTemplate::new(200).set_body_json(json!({
            "model_attestations": [{
                "request_nonce": nonce,
                "signing_algo": "ecdsa",
                "signing_address": "22".repeat(20),
                "intel_quote": "aa",
                "event_log": [],
                "info": {"tcb_info": {"app_compose": "{}"}},
                "nvidia_payload": null,
            }]
        }))
    }
}

#[derive(Clone)]
struct GatewayAttestationResponder;

impl Respond for GatewayAttestationResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let nonce = request
            .url
            .query_pairs()
            .find(|(key, _)| key == "nonce")
            .map(|(_, value)| value.into_owned())
            .expect("request contains a nonce");
        let has_tls_fingerprint = request
            .url
            .query_pairs()
            .any(|(key, value)| key == "include_tls_fingerprint" && value == "true");
        let mut attestation = json!({
            "request_nonce": nonce,
            "signing_algo": "ed25519",
            "signing_address": "22".repeat(32),
            "intel_quote": "aa",
            "event_log": [],
            "report_data": "00".repeat(64),
            "info": {"tcb_info": {"app_compose": "{}"}},
        });
        if has_tls_fingerprint {
            attestation["tls_cert_fingerprint"] = json!("33".repeat(32));
        }
        ResponseTemplate::new(200).set_body_json(json!({
            "gateway_attestation": attestation,
        }))
    }
}

fn base_url(server: &MockServer) -> String {
    format!("{}/v1", server.uri())
}

fn test_api_key() -> &'static str {
    static CONFIGURE_LOCAL_REQUESTS: Once = Once::new();
    CONFIGURE_LOCAL_REQUESTS.call_once(|| {
        std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
        std::env::set_var("no_proxy", "127.0.0.1,localhost");
    });
    "test-key"
}

fn client(server: &MockServer) -> AttestationClient {
    AttestationClient::with_base_url(test_api_key().to_owned(), &base_url(server)).unwrap()
}

fn model_attestation_for_signer(signer: SigningIdentity) -> ModelAttestation {
    ModelAttestation {
        evidence: AttestationEvidence {
            nonce: "11".repeat(32),
            signer,
            intel_quote: "aa".to_owned(),
            event_log: AttestationEventLog::Entries(vec![]),
            app_compose: "{}".to_owned(),
        },
        reported_quote_data: None,
        nvidia_payload: None,
    }
}

fn signature_for_evidence_selection(
    kind: CompletionSignatureKind,
    signer: SigningIdentity,
) -> CompletionSignature {
    CompletionSignature {
        kind,
        signer,
        signed_text: "not used when selecting evidence".to_owned(),
        signature: "00".repeat(64),
    }
}

#[test]
fn model_attestation_selection_rejects_zero_or_multiple_matches() {
    let signature = signature_for_evidence_selection(
        CompletionSignatureKind::ProviderTee,
        SigningIdentity {
            signing_algo: SigningAlgo::Ecdsa,
            signing_address: "22".repeat(20),
        },
    );
    let candidate = model_attestation_for_signer(signature.signer.clone());
    let candidates = vec![candidate.clone(), candidate];

    let error = find_model_attestation_for_signature(&candidates, &signature).unwrap_err();

    assert!(matches!(
        error,
        SdkError::Api(ApiError::AmbiguousModelAttestationSigner {
            matching_count: 2,
            total_count: 2,
        })
    ));

    let error = find_model_attestation_for_signature(&[], &signature).unwrap_err();
    let SdkError::Api(error) = error else {
        panic!("missing model evidence must return an ApiError");
    };
    assert!(matches!(error, ApiError::ModelAttestationSignerNotFound));
    assert_eq!(error.code(), "api.model_attestation_signer_not_found");
}

#[test]
fn finds_a_signer_with_an_equivalent_hex_address() {
    let signature = signature_for_evidence_selection(
        CompletionSignatureKind::ProviderTee,
        SigningIdentity {
            signing_algo: SigningAlgo::Ecdsa,
            signing_address: format!("0X{}", "AB".repeat(20)),
        },
    );
    let candidate = model_attestation_for_signer(SigningIdentity {
        signing_algo: SigningAlgo::Ecdsa,
        signing_address: "ab".repeat(20),
    });
    let candidates = [candidate];

    let selected = find_model_attestation_for_signature(&candidates, &signature).unwrap();

    assert_eq!(selected.evidence.signer.signing_address, "ab".repeat(20));
}

#[test]
fn rejects_a_gateway_signature_when_selecting_model_attestation() {
    let signature = signature_for_evidence_selection(
        CompletionSignatureKind::Gateway,
        SigningIdentity {
            signing_algo: SigningAlgo::Ecdsa,
            signing_address: "22".repeat(20),
        },
    );

    let error = find_model_attestation_for_signature(&[], &signature).unwrap_err();

    assert!(matches!(
        error,
        SdkError::Verification(VerificationError::SignatureKindMismatch {
            expected: CompletionSignatureKind::ProviderTee,
            actual: CompletionSignatureKind::Gateway,
        })
    ));
}

#[test]
fn client_rejects_an_invalid_base_url() {
    let result = AttestationClient::with_base_url("test-key".to_owned(), "://invalid");

    assert!(matches!(
        result,
        Err(VerificationError::InvalidInput { ref field, .. }) if field == "base_url"
    ));
}

#[tokio::test]
async fn client_treats_a_missing_model_candidate_list_as_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let error = client(&server)
        .fetch_model_attestations("glm-5.2", None, None)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        SdkError::Api(ApiError::UnexpectedModelAttestationCount { actual_count: 0 })
    ));
}

#[tokio::test]
async fn client_fetches_model_attestations_with_a_fresh_nonce() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("model", "glm-5.2"))
        .and(query_param("provider", "near"))
        .and(query_param("include_tls_fingerprint", "false"))
        .and(query_param_is_missing("signing_algo"))
        .and(query_param_is_missing("signing_address"))
        .and(header("x-no-aliasing", "true"))
        .respond_with(ModelAttestationResponder)
        .mount(&server)
        .await;

    let fetched = client(&server)
        .fetch_model_attestations("glm-5.2", None, None)
        .await
        .unwrap();

    assert_eq!(fetched.attestations.len(), 1);
    assert_eq!(
        fetched.attestations[0].evidence.nonce,
        fetched.client_binding.nonce
    );
    assert_eq!(fetched.attestations[0].nvidia_payload, None);
}

#[tokio::test]
async fn client_fetches_model_attestation_for_a_provider_signature() {
    let server = MockServer::start().await;
    let signing_address = "22".repeat(20);
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("model", "glm-5.2"))
        .and(query_param("signing_algo", "ecdsa"))
        .and(query_param("signing_address", signing_address.clone()))
        .respond_with(ModelAttestationResponder)
        .mount(&server)
        .await;
    let signature = signature_for_evidence_selection(
        CompletionSignatureKind::ProviderTee,
        SigningIdentity {
            signing_algo: SigningAlgo::Ecdsa,
            signing_address,
        },
    );

    let fetched = client(&server)
        .fetch_model_attestation_for_signature("glm-5.2", &signature)
        .await
        .unwrap();

    assert_eq!(fetched.attestation.evidence.signer, signature.signer);
}

#[tokio::test]
async fn client_fetches_tls_bound_gateway_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("include_tls_fingerprint", "true"))
        .and(query_param_is_missing("signing_algo"))
        .respond_with(GatewayAttestationResponder)
        .mount(&server)
        .await;

    let fetched = client(&server)
        .fetch_gateway_attestation(None, Default::default())
        .await
        .unwrap();

    assert_eq!(
        fetched.attestation.evidence.nonce,
        fetched.client_binding.nonce
    );
    assert_eq!(
        fetched.attestation.tls_spki_fingerprint,
        Some("33".repeat(32))
    );
    assert_eq!(fetched.client_binding.peer_spki_fingerprint, None);
    assert!(fetched.policy.verify_tls_binding);
}

#[tokio::test]
async fn client_can_fetch_gateway_evidence_without_tls_binding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("include_tls_fingerprint", "false"))
        .respond_with(GatewayAttestationResponder)
        .mount(&server)
        .await;
    let policy = GatewayAttestationPolicy {
        verify_tls_binding: false,
        ..Default::default()
    };

    let fetched = client(&server)
        .fetch_gateway_attestation(None, policy)
        .await
        .unwrap();

    assert_eq!(fetched.attestation.tls_spki_fingerprint, None);
    assert!(!fetched.policy.verify_tls_binding);
}

#[tokio::test]
async fn client_rejects_gateway_evidence_missing_requested_tls_fingerprint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("include_tls_fingerprint", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "gateway_attestation": {
                "request_nonce": "00".repeat(32),
                "signing_algo": "ed25519",
                "signing_address": "22".repeat(32),
                "intel_quote": "aa",
                "event_log": [],
                "report_data": "00".repeat(64),
                "info": {"tcb_info": {"app_compose": "{}"}},
            }
        })))
        .mount(&server)
        .await;

    let error = client(&server)
        .fetch_gateway_attestation(None, Default::default())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        SdkError::Api(ApiError::InvalidResponse { ref path, .. })
            if path == "gateway_attestation.tls_cert_fingerprint"
    ));
}

#[tokio::test]
async fn client_applies_a_gateway_signing_algorithm_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("signing_algo", "ed25519"))
        .and(query_param("include_tls_fingerprint", "true"))
        .respond_with(GatewayAttestationResponder)
        .mount(&server)
        .await;

    client(&server)
        .fetch_gateway_attestation(Some(SigningAlgo::Ed25519), Default::default())
        .await
        .unwrap();
}

#[tokio::test]
async fn client_preserves_completion_signature_kind_and_unavailable_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/signature/found"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "text": "signed",
            "signature": "aa",
            "signing_address": "22".repeat(32),
            "signing_algo": "ed25519",
            "signature_kind": "gateway",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/signature/pending"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "error_code": "pending",
            "message": "not ready",
        })))
        .mount(&server)
        .await;

    let client = client(&server);
    let found = client
        .lookup_completion_signature("found", None)
        .await
        .unwrap();
    assert!(matches!(
        found,
        CompletionSignatureLookup::Found(CompletionSignature {
            kind: CompletionSignatureKind::Gateway,
            ..
        })
    ));

    let pending = client
        .lookup_completion_signature("pending", None)
        .await
        .unwrap();
    assert!(matches!(
        pending,
        CompletionSignatureLookup::Unavailable(SignatureUnavailable { ref error_code, .. })
            if error_code == "pending"
    ));

    let error = client
        .fetch_completion_signature("pending", None)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SdkError::Api(ApiError::CompletionSignatureUnavailable { ref provider_error_code })
            if provider_error_code == "pending"
    ));
}

#[tokio::test]
async fn client_applies_a_completion_signature_algorithm_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/signature/found"))
        .and(query_param("signing_algo", "ed25519"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "text": "signed",
            "signature": "aa",
            "signing_address": "22".repeat(32),
            "signing_algo": "ed25519",
            "signature_kind": "gateway",
        })))
        .mount(&server)
        .await;

    client(&server)
        .lookup_completion_signature("found", Some(SigningAlgo::Ed25519))
        .await
        .unwrap();
}
