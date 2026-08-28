use async_trait::async_trait;
use serde_json::json;
use std::sync::Once;
use verifiable_ai_sdk::{
    find_model_attestation_for_signature, ApiError, ApiTransportReason, AttestationEventLog,
    AttestationEvidence, CompletionSignature, CompletionSignatureKind, CompletionSignatureLookup,
    CompletionSignatureReference, CompletionSignatureRequest, GatewayAttestationRequest,
    GatewayAttestationTransport, GatewayAttestationTransportRequest,
    GatewayAttestationTransportResponse, ModelAttestation, ModelAttestationForSignatureRequest,
    ModelAttestationsRequest, SdkError, SignatureUnavailable, SigningAlgo, SigningIdentity,
    VerificationError,
};
use wiremock::{
    matchers::{header, method, path, query_param},
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
        ResponseTemplate::new(200).set_body_json(json!({
            "gateway_attestation": {
                "request_nonce": nonce,
                "signing_algo": "ed25519",
                "signing_address": "22".repeat(32),
                "intel_quote": "aa",
                "event_log": [],
                "tls_cert_fingerprint": "33".repeat(32),
                "report_data": "00".repeat(64),
                "info": {"tcb_info": {"app_compose": "{}"}},
            }
        }))
    }
}

struct TlsAwareGatewayTransport;

#[async_trait]
impl GatewayAttestationTransport for TlsAwareGatewayTransport {
    async fn get(
        &self,
        request: GatewayAttestationTransportRequest,
    ) -> Result<GatewayAttestationTransportResponse, ApiTransportReason> {
        assert_eq!(request.url.path(), "/v1/attestation/report");
        assert_eq!(
            request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer test-key")
        );
        let query = request
            .url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            query.get("signing_algo").map(|value| value.as_ref()),
            Some("ed25519")
        );
        assert_eq!(
            query
                .get("include_tls_fingerprint")
                .map(|value| value.as_ref()),
            Some("true")
        );
        let nonce = query.get("nonce").expect("request contains a nonce");
        Ok(GatewayAttestationTransportResponse {
            status: 200,
            body: json!({
                "gateway_attestation": {
                    "request_nonce": nonce,
                    "signing_algo": "ed25519",
                    "signing_address": "22".repeat(32),
                    "intel_quote": "aa",
                    "event_log": [],
                    "tls_cert_fingerprint": "33".repeat(32),
                    "report_data": "00".repeat(64),
                    "info": {"tcb_info": {"app_compose": "{}"}},
                }
            })
            .to_string(),
            peer_spki_fingerprint: Some("33".repeat(32)),
        })
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

fn model_attestation_for_signer(signer: SigningIdentity) -> ModelAttestation {
    ModelAttestation {
        evidence: AttestationEvidence {
            nonce: "11".repeat(32),
            signer,
            intel_quote: "aa".to_owned(),
            event_log: AttestationEventLog::Entries(vec![]),
            app_compose: "{}".to_owned(),
            declared_spki_fingerprint: None,
        },
        reported_quote_data: None,
        nvidia_payload: None,
    }
}

#[test]
fn finds_exactly_one_model_attestation_for_a_signature() {
    let signature = CompletionSignatureReference {
        kind: CompletionSignatureKind::ProviderTee,
        signer: SigningIdentity {
            signing_algo: SigningAlgo::Ecdsa,
            signing_address: "22".repeat(20),
        },
    };
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
    let signature = CompletionSignatureReference {
        kind: CompletionSignatureKind::ProviderTee,
        signer: SigningIdentity {
            signing_algo: SigningAlgo::Ecdsa,
            signing_address: format!("0X{}", "AB".repeat(20)),
        },
    };
    let candidate = model_attestation_for_signer(SigningIdentity {
        signing_algo: SigningAlgo::Ecdsa,
        signing_address: "ab".repeat(20),
    });
    let candidates = [candidate];

    let selected = find_model_attestation_for_signature(&candidates, &signature).unwrap();

    assert_eq!(selected.evidence.signer.signing_address, "ab".repeat(20));
}

#[test]
fn request_builders_reject_an_invalid_base_url() {
    let result = ModelAttestationsRequest::new("test-key", "glm-5.2").base_url("://invalid");

    assert!(matches!(
        result,
        Err(VerificationError::InvalidInput { ref field, .. }) if field == "base_url"
    ));
}

#[tokio::test]
async fn model_attestation_request_rejects_an_empty_candidate_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model_attestations": [],
        })))
        .mount(&server)
        .await;

    let error = ModelAttestationsRequest::new(test_api_key(), "glm-5.2")
        .base_url(base_url(&server))
        .unwrap()
        .send()
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        SdkError::Api(ApiError::UnexpectedModelAttestationCount { actual_count: 0 })
    ));
}

#[tokio::test]
async fn model_attestation_request_returns_a_fresh_nonce_and_normalized_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("model", "glm-5.2"))
        .and(query_param("provider", "near"))
        .and(header("x-no-aliasing", "true"))
        .respond_with(ModelAttestationResponder)
        .mount(&server)
        .await;

    let fetched = ModelAttestationsRequest::new(test_api_key(), "glm-5.2")
        .base_url(base_url(&server))
        .unwrap()
        .send()
        .await
        .unwrap();

    assert_eq!(fetched.attestations.len(), 1);
    assert_eq!(fetched.attestations[0].evidence.nonce, fetched.nonce);
    assert_eq!(fetched.attestations[0].nvidia_payload, None);
}

#[tokio::test]
async fn model_attestation_request_applies_signer_filters() {
    let server = MockServer::start().await;
    let signing_address = "22".repeat(20);
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("signing_algo", "ecdsa"))
        .and(query_param("signing_address", signing_address.clone()))
        .respond_with(ModelAttestationResponder)
        .mount(&server)
        .await;

    let fetched = ModelAttestationsRequest::new(test_api_key(), "glm-5.2")
        .base_url(base_url(&server))
        .unwrap()
        .signing_algo(SigningAlgo::Ecdsa)
        .signing_address(signing_address)
        .send()
        .await
        .unwrap();

    assert_eq!(fetched.attestations.len(), 1);
}

#[tokio::test]
async fn model_attestation_for_signature_request_uses_the_signature_signer() {
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
    let signature = CompletionSignatureReference {
        kind: CompletionSignatureKind::ProviderTee,
        signer: SigningIdentity {
            signing_algo: SigningAlgo::Ecdsa,
            signing_address,
        },
    };

    let fetched = ModelAttestationForSignatureRequest::new(test_api_key(), "glm-5.2", &signature)
        .base_url(base_url(&server))
        .unwrap()
        .send()
        .await
        .unwrap();

    assert_eq!(fetched.attestation.evidence.signer, signature.signer);
}

#[tokio::test]
async fn gateway_attestation_request_requests_tls_bound_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation/report"))
        .and(query_param("include_tls_fingerprint", "true"))
        .and(query_param("signing_algo", "ed25519"))
        .respond_with(GatewayAttestationResponder)
        .mount(&server)
        .await;

    let fetched = GatewayAttestationRequest::new(test_api_key())
        .base_url(base_url(&server))
        .unwrap()
        .send()
        .await
        .unwrap();

    assert_eq!(fetched.attestation.evidence.nonce, fetched.nonce);
    assert_eq!(
        fetched.attestation.evidence.declared_spki_fingerprint,
        Some("33".repeat(32))
    );
    assert_eq!(fetched.peer_spki_fingerprint, None);
}

#[tokio::test]
async fn gateway_attestation_request_returns_the_peer_from_a_custom_transport() {
    let fetched = GatewayAttestationRequest::new("test-key")
        .base_url("https://cloud.example/v1")
        .unwrap()
        .transport(TlsAwareGatewayTransport)
        .send()
        .await
        .unwrap();

    assert_eq!(fetched.peer_spki_fingerprint, Some("33".repeat(32)));
}

#[tokio::test]
async fn completion_signature_request_preserves_kind_and_unavailable_response() {
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

    let found = CompletionSignatureRequest::new(test_api_key(), "found")
        .base_url(base_url(&server))
        .unwrap()
        .lookup()
        .await
        .unwrap();
    assert!(matches!(
        found,
        CompletionSignatureLookup::Found(CompletionSignature {
            kind: CompletionSignatureKind::Gateway,
            ..
        })
    ));

    let fetched = CompletionSignatureRequest::new(test_api_key(), "found")
        .base_url(base_url(&server))
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(fetched.kind, CompletionSignatureKind::Gateway);

    let pending = CompletionSignatureRequest::new(test_api_key(), "pending")
        .base_url(base_url(&server))
        .unwrap()
        .lookup()
        .await
        .unwrap();
    assert!(matches!(
        pending,
        CompletionSignatureLookup::Unavailable(SignatureUnavailable { ref error_code, .. })
            if error_code == "pending"
    ));

    let error = CompletionSignatureRequest::new(test_api_key(), "pending")
        .base_url(base_url(&server))
        .unwrap()
        .send()
        .await
        .unwrap_err();
    let SdkError::Api(error) = error else {
        panic!("strict signature fetch must return an ApiError");
    };
    assert!(matches!(
        error,
        ApiError::CompletionSignatureUnavailable { ref provider_error_code }
            if provider_error_code == "pending"
    ));
    assert_eq!(error.code(), "api.completion_signature_unavailable");
    assert!(!error.retryable());
}

#[tokio::test]
async fn completion_signature_request_applies_a_signing_algorithm() {
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

    let signature = CompletionSignatureRequest::new(test_api_key(), "found")
        .base_url(base_url(&server))
        .unwrap()
        .signing_algo(SigningAlgo::Ed25519)
        .send()
        .await
        .unwrap();

    assert_eq!(signature.kind, CompletionSignatureKind::Gateway);
}
