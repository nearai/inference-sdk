use serde_json::json;
use std::sync::Once;
use verifiable_ai_sdk::{
    find_model_attestation_for_signature, ApiError, AttestationClient, AttestationEventLog,
    AttestationEvidence, CompletionSignature, CompletionSignatureKind,
    GatewayAttestationFetchOptions, ModelAttestation, SigningAlgo, SigningIdentity,
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
        ApiError::AmbiguousModelAttestationSigner {
            matching_count: 2,
            total_count: 2,
        }
    ));

    let error = find_model_attestation_for_signature(&[], &signature).unwrap_err();
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

#[tokio::test]
async fn selection_and_client_reject_a_non_provider_signature_as_api_input() {
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
        ApiError::InvalidInput {
            ref field,
            ref reason,
            expected: Some(ref expected),
            actual: Some(ref actual),
        } if field == "signature.kind"
            && reason == "unsupported_value"
            && expected == "provider_tee"
            && actual == "gateway"
    ));

    let server = MockServer::start().await;
    let error = client(&server)
        .fetch_model_attestation_for_signature("glm-5.2", &signature)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        ApiError::InvalidInput {
            ref field,
            ref reason,
            expected: Some(ref expected),
            actual: Some(ref actual),
        } if field == "signature.kind"
            && reason == "unsupported_value"
            && expected == "provider_tee"
            && actual == "gateway"
    ));
}

#[test]
fn selection_rejects_a_malformed_signer_as_api_input() {
    let signature = signature_for_evidence_selection(
        CompletionSignatureKind::ProviderTee,
        SigningIdentity {
            signing_algo: SigningAlgo::Ecdsa,
            signing_address: "not hexadecimal".to_owned(),
        },
    );

    let error = find_model_attestation_for_signature(&[], &signature).unwrap_err();

    assert!(matches!(
        error,
        ApiError::InvalidInput {
            ref field,
            ref reason,
            expected: None,
            actual: None,
        } if field == "signature.signer.signing_address"
            && reason == "invalid_hex"
    ));
}

#[test]
fn selection_rejects_a_malformed_candidate_signer_as_api_input() {
    let signature = signature_for_evidence_selection(
        CompletionSignatureKind::ProviderTee,
        SigningIdentity {
            signing_algo: SigningAlgo::Ecdsa,
            signing_address: "22".repeat(20),
        },
    );
    let candidates = [model_attestation_for_signer(SigningIdentity {
        signing_algo: SigningAlgo::Ecdsa,
        signing_address: "not hexadecimal".to_owned(),
    })];

    let error = find_model_attestation_for_signature(&candidates, &signature).unwrap_err();

    assert!(matches!(
        error,
        ApiError::InvalidInput {
            ref field,
            ref reason,
            expected: None,
            actual: None,
        } if field == "attestations[0].signer.signing_address" && reason == "invalid_hex"
    ));
}

#[test]
fn client_rejects_an_invalid_base_url_as_api_input() {
    for base_url in ["://invalid", "/v1", "ftp://cloud.example/v1"] {
        let result = AttestationClient::with_base_url("test-key".to_owned(), base_url);

        assert!(matches!(
            result,
            Err(ApiError::InvalidInput {
                ref field,
                ref reason,
                expected: Some(_),
                actual: None,
            }) if field == "base_url" && reason == "invalid_url"
        ));
    }
}

#[tokio::test]
async fn client_rejects_an_invalid_api_key_as_api_input() {
    let server = MockServer::start().await;
    let client = AttestationClient::with_base_url("bad\nkey".to_owned(), &base_url(&server))
        .expect("the mock server URL is valid");

    let error = client
        .fetch_completion_signature("completion", None)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        ApiError::InvalidInput {
            ref field,
            ref reason,
            expected: Some(ref expected),
            actual: None,
        } if field == "api_key"
            && reason == "invalid_header_value"
            && expected == "an HTTP header value"
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
        ApiError::UnexpectedModelAttestationCount { actual_count: 0 }
    ));
}

#[tokio::test]
async fn client_accepts_both_unfiltered_signing_address_lengths() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .respond_with(ModelAttestationResponder)
        .mount(&server)
        .await;
    let client = client(&server);

    for signing_address in ["22".repeat(20), "22".repeat(32)] {
        client
            .fetch_model_attestations("glm-5.2", None, Some(&signing_address))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn client_rejects_invalid_model_signing_address_filters_before_request() {
    let server = MockServer::start().await;
    let client = client(&server);
    let unsupported_length = "22".repeat(19);

    let error = client
        .fetch_model_attestations("glm-5.2", None, Some(&unsupported_length))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ApiError::InvalidInput {
            ref field,
            ref reason,
            expected: Some(ref expected),
            actual: Some(ref actual),
        } if field == "signing_address"
            && reason == "wrong_length"
            && expected == "a 20- or 32-byte hexadecimal signing address"
            && actual == "19 bytes"
    ));

    let ecdsa_mismatch = "22".repeat(32);
    let error = client
        .fetch_model_attestations("glm-5.2", Some(SigningAlgo::Ecdsa), Some(&ecdsa_mismatch))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ApiError::InvalidInput {
            ref field,
            ref reason,
            expected: Some(ref expected),
            actual: Some(ref actual),
        } if field == "signing_address"
            && reason == "wrong_length"
            && expected == "20-byte hexadecimal signing address"
            && actual == "32 bytes"
    ));

    let error = client
        .fetch_model_attestations("glm-5.2", None, Some("not hexadecimal"))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ApiError::InvalidInput {
            ref field,
            ref reason,
            expected: None,
            actual: None,
        } if field == "signing_address" && reason == "invalid_hex"
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
async fn client_fetches_tls_bound_gateway_attestation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("include_tls_fingerprint", "true"))
        .and(query_param_is_missing("signing_algo"))
        .respond_with(GatewayAttestationResponder)
        .mount(&server)
        .await;

    let fetched = client(&server)
        .fetch_gateway_attestation(Default::default())
        .await
        .unwrap();

    assert_eq!(
        fetched.attestation.evidence.nonce,
        fetched.client_binding.nonce
    );
    assert_eq!(fetched.attestation.spki_fingerprint, Some("33".repeat(32)));
    assert_eq!(fetched.client_binding.spki_fingerprint, None);
}

#[tokio::test]
async fn client_can_fetch_gateway_attestation_without_an_spki_fingerprint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("include_tls_fingerprint", "false"))
        .respond_with(GatewayAttestationResponder)
        .mount(&server)
        .await;
    let options = GatewayAttestationFetchOptions {
        include_spki_fingerprint: false,
        ..Default::default()
    };

    let fetched = client(&server)
        .fetch_gateway_attestation(options)
        .await
        .unwrap();

    assert_eq!(fetched.attestation.spki_fingerprint, None);
    assert_eq!(fetched.client_binding.spki_fingerprint, None);
}

#[tokio::test]
async fn client_rejects_gateway_attestation_missing_requested_tls_fingerprint() {
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
        .fetch_gateway_attestation(Default::default())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        ApiError::InvalidResponse {
            ref path,
            ref expected,
            ref actual,
        } if path == "gateway_attestation.tls_cert_fingerprint"
            && expected == "present"
            && actual == "missing"
    ));
}

#[tokio::test]
async fn client_rejects_an_unrequested_gateway_spki_fingerprint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("include_tls_fingerprint", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "gateway_attestation": {
                "request_nonce": "00".repeat(32),
                "signing_algo": "ed25519",
                "signing_address": "22".repeat(32),
                "intel_quote": "aa",
                "event_log": [],
                "report_data": "00".repeat(64),
                "tls_cert_fingerprint": "33".repeat(32),
                "info": {"tcb_info": {"app_compose": "{}"}},
            }
        })))
        .mount(&server)
        .await;

    let options = GatewayAttestationFetchOptions {
        include_spki_fingerprint: false,
        ..Default::default()
    };
    let error = client(&server)
        .fetch_gateway_attestation(options)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        ApiError::InvalidResponse {
            ref path,
            ref expected,
            ref actual,
        } if path == "gateway_attestation.tls_cert_fingerprint"
            && expected == "missing"
            && actual == "present"
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
        .fetch_gateway_attestation(GatewayAttestationFetchOptions {
            signing_algo: Some(SigningAlgo::Ed25519),
            ..Default::default()
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn client_fetches_a_completion_signature_and_reports_an_unavailable_response() {
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
        .and(path("/v1/signature/unavailable"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "error_code": "SIGNATURE_UNSUPPORTED",
            "message": "the provider does not support completion signatures",
        })))
        .mount(&server)
        .await;

    let client = client(&server);
    let found = client
        .fetch_completion_signature("found", None)
        .await
        .unwrap();
    assert!(matches!(
        found,
        CompletionSignature {
            kind: CompletionSignatureKind::Gateway,
            ..
        }
    ));

    let error = client
        .fetch_completion_signature("unavailable", None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "api.completion_signature_unavailable");
    assert!(!error.retryable());
    assert!(matches!(
        error,
        ApiError::CompletionSignatureUnavailable {
            ref provider_error_code,
            ref provider_message,
        } if provider_error_code == "SIGNATURE_UNSUPPORTED"
            && provider_message == "the provider does not support completion signatures"
    ));
}

#[tokio::test]
async fn client_marks_a_completion_signature_404_as_retryable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/signature/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let error = client(&server)
        .fetch_completion_signature("missing", None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "api.http_status");
    assert!(error.retryable());
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
        .fetch_completion_signature("found", Some(SigningAlgo::Ed25519))
        .await
        .unwrap();
}
