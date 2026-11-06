#[path = "inference/direct_inference_client.rs"]
mod direct_inference_client;
#[path = "support/inference.rs"]
mod fixture;
#[path = "inference/messages.rs"]
mod messages;
#[path = "inference/responses.rs"]
mod responses;
mod support;
#[path = "inference/systemone.rs"]
mod systemone;

use async_trait::async_trait;
use fixture::{
    body, ohttp_config, response_request_body, setup, systemone_request, Fixture, Quote,
};
use futures_util::StreamExt;
use nearai_inference_sdk::*;
use serde_json::json;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn chat_http_errors_keep_completion_resource_and_retryability() {
    for status in [429, 503] {
        let (server, _, options) = setup(Fixture::default()).await;
        Mock::given(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(status))
            .with_priority(1)
            .mount(&server)
            .await;
        let client = InferenceClient::with_options(options).unwrap();
        let error = client.chat_completions(body()).await.unwrap_err();
        assert!(error.retryable(), "{error}");
        assert!(matches!(
            error,
            InferenceError::Api(ApiError::HttpStatus {
                resource: ApiResource::Completion,
                status: actual,
                ..
            }) if actual == status
        ));
    }
}

#[tokio::test]
async fn verifies_before_chat_and_retains_exact_bytes_and_cached_evidence() {
    let (_server, f, options) = setup(Fixture::default()).await;
    let client = InferenceClient::with_options(options).unwrap();
    let first = client.verify("vendor/model").await.unwrap();
    let second = client.verify("vendor/model").await.unwrap();
    assert_eq!(first.verified_at, second.verified_at);
    assert_eq!(first.models.len(), 1);
    let completion = client.chat_completions(body()).await.unwrap();
    let id = completion["id"].as_str().unwrap();
    let verified = client.verify_response(id).await.unwrap();
    assert_eq!(
        verified.signature_kind(),
        CompletionSignatureKind::ProviderTee
    );
    client.verify_response(id).await.unwrap();
    assert_eq!(f.gateway.load(Ordering::SeqCst), 1);
    assert_eq!(f.signatures.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn gateway_shared_signer_preserves_all_verified_reports() {
    let (_server, fixture, options) = setup(Fixture {
        shared_model: true,
        extra_model: true,
        ..Default::default()
    })
    .await;
    let client = InferenceClient::with_options(options).unwrap();
    let preflight = client.verify("vendor/model").await.unwrap();
    assert_eq!(preflight.models.len(), 3);
    assert_ne!(preflight.models[0], preflight.models[2]);
    assert_eq!(
        preflight.models[0].evidence.signer,
        preflight.models[2].evidence.signer
    );
    assert_ne!(
        preflight.models[0].evidence.signer,
        preflight.models[1].evidence.signer
    );
    let expected = vec![preflight.models[0].clone(), preflight.models[2].clone()];
    client.chat_completions(body()).await.unwrap();
    let receipt = client.verify_response("chat-0").await.unwrap();
    assert_eq!(receipt.attestations, expected);
    // The deprecated representative remains available to existing callers.
    #[allow(deprecated)]
    let has_legacy_representative =
        matches!(receipt.attestation, VerifiedCompletionAttestation::Model(_));
    assert!(has_legacy_representative);
    assert_eq!(
        client.verify_response("chat-0").await.unwrap().attestations,
        expected
    );
    assert_eq!(fixture.model.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.signatures.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn gateway_stream_receipt_keeps_gateway_evidence_with_attested_models() {
    let (_server, _fixture, options) = setup(Fixture {
        shared_model: true,
        gateway_chat_receipt: true,
        ..Default::default()
    })
    .await;
    let client = InferenceClient::with_options(options).unwrap();
    let preflight = client.verify("vendor/model").await.unwrap();
    assert_eq!(preflight.models.len(), 2);
    let mut request = body();
    request["stream"] = json!(true);
    client
        .send(client.chat_request(request).unwrap())
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let receipt = client.verify_response("chat-0").await.unwrap();
    assert_eq!(receipt.signature_kind(), CompletionSignatureKind::Gateway);
    assert!(receipt.attestations.is_empty());
    let VerifiedCompletionAttestation::Gateway(gateway) = receipt.attestation else {
        panic!("gateway receipt must retain gateway evidence");
    };
    assert_eq!(gateway, preflight.gateway);
}

#[tokio::test]
async fn gateway_shared_signer_rejects_second_report_evidence_and_policy_failures() {
    struct RejectSecond(AtomicUsize);
    #[async_trait]
    impl DeploymentVerifier for RejectSecond {
        async fn verify(&self, _: &MeasuredDeployment) -> Result<(), VerificationError> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 1 {
                return Err(VerificationError::DeploymentProvenanceRejected);
            }
            Ok(())
        }
    }
    for bad_evidence in [true, false] {
        let (_server, fixture, mut options) = setup(Fixture {
            shared_model: true,
            bad_model: bad_evidence,
            ..Default::default()
        })
        .await;
        if !bad_evidence {
            options.model_verification.deployment =
                Some(Arc::new(RejectSecond(AtomicUsize::new(0))));
        }
        let client = InferenceClient::with_options(options).unwrap();
        assert!(client.chat_completions(body()).await.is_err());
        assert_eq!(fixture.chat.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn gateway_receipt_rejects_another_verified_routing_key() {
    let (_server, _fixture, options) = setup(Fixture {
        extra_model: true,
        ..Default::default()
    })
    .await;
    let client = InferenceClient::with_options(options).unwrap();
    assert_eq!(client.verify("vendor/model").await.unwrap().models.len(), 2);
    // The first key (seed 8) is selected, but the fixture signs with seed 7.
    client.chat_completions(body()).await.unwrap();
    assert_eq!(
        client.verify_response("chat-0").await.unwrap_err().code(),
        "signature.signer_mismatch"
    );
}

#[tokio::test]
async fn gateway_receipt_keeps_its_original_signer_group_after_refresh() {
    let (_server, fixture, mut options) = setup(Fixture {
        shared_model: true,
        ..Default::default()
    })
    .await;
    options.attestation_cache_ttl = Duration::ZERO;
    let client = InferenceClient::with_options(options).unwrap();
    client.chat_completions(body()).await.unwrap();
    let refreshed = client.verify("vendor/model").await.unwrap();
    assert!(refreshed.models[1]
        .evidence
        .advisory_ids
        .iter()
        .any(|id| id == "shared-1"));
    let receipt = client.verify_response("chat-0").await.unwrap();
    assert_eq!(receipt.attestations.len(), 2);
    assert!(receipt.attestations[1]
        .evidence
        .advisory_ids
        .iter()
        .any(|id| id == "shared-0"));
    assert_eq!(fixture.model.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn gateway_verification_precedes_authenticated_requests() {
    struct CheckingGateway {
        server: Arc<MockServer>,
        reject: bool,
    }
    #[async_trait]
    impl TdxQuoteVerifier for CheckingGateway {
        async fn verify(
            &self,
            quote: &str,
        ) -> Result<TdxQuoteVerificationResult, VerificationError> {
            // Leave the verifier pending while the executor can poll other work.
            tokio::time::sleep(Duration::from_millis(30)).await;
            let requests = self.server.received_requests().await.unwrap();
            assert_eq!(
                requests.len(),
                1,
                "credentials sent before Gateway verification"
            );
            assert!(requests[0].headers.get("authorization").is_none());
            if self.reject {
                return Err(VerificationError::DebugEnabled);
            }
            Quote.verify(quote).await
        }
    }
    for reject in [false, true] {
        let (server, fixture, mut options) = setup(Fixture::default()).await;
        let server = Arc::new(server);
        options.gateway_verification.tdx_quote = Some(Arc::new(CheckingGateway {
            server: server.clone(),
            reject,
        }));
        let client = InferenceClient::with_options(options).unwrap();
        let result = client.verify("vendor/model").await;
        if reject {
            assert_eq!(result.unwrap_err().code(), "policy.debug_enabled");
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        } else {
            result.unwrap();
            assert_eq!(fixture.model.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn clear_response_cache_preserves_session_and_applies_to_clones() {
    for tee in [false, true] {
        let fixture = Fixture::default();
        if !tee {
            *fixture.metadata.lock().unwrap() = Some(json!({
                "metadata": {"providerType": "external", "attestationSupported": false}
            }));
        }
        let (_server, f, options) = setup(fixture).await;
        let client = InferenceClient::with_options(options).unwrap();
        let first = client.chat_completions(body()).await.unwrap();
        let id = first["id"].as_str().unwrap();
        client.verify_response(id).await.unwrap();
        client.clone().clear_response_cache().await;
        client.clear_response_cache().await;
        assert_eq!(
            client.verify_response(id).await.unwrap_err().code(),
            "api.completion_not_found"
        );

        let next = client.chat_completions(body()).await.unwrap();
        client
            .verify_response(next["id"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(f.gateway.load(Ordering::SeqCst), 1);
        assert_eq!(f.model.load(Ordering::SeqCst), usize::from(tee));
    }
}

#[tokio::test]
async fn clear_response_cache_allows_reusing_response_and_decision_ids() {
    let (_server, _f, options) = setup(Fixture::default()).await;
    let client = InferenceClient::with_options(options).unwrap();
    for _ in 0..2 {
        let response = client
            .create_response(response_request_body(false))
            .await
            .unwrap();
        let decision = client.systemone_create(&systemone_request()).await.unwrap();
        let ids = [
            response["id"].as_str().unwrap(),
            decision.decision_id.as_str(),
        ];
        for id in ids {
            client.verify_response(id).await.unwrap();
        }
        client.clear_response_cache().await;
        for id in ids {
            assert_eq!(
                client.verify_response(id).await.unwrap_err().code(),
                "api.completion_not_found"
            );
        }
    }
}

#[tokio::test]
async fn clear_response_cache_during_stream_prevents_late_registration() {
    for responses in [false, true] {
        let (_server, _f, options) = setup(Fixture::default()).await;
        let client = InferenceClient::with_options(options).unwrap();
        let (request, id) = if responses {
            (
                client
                    .response_request(response_request_body(true))
                    .unwrap(),
                "resp_fixture",
            )
        } else {
            let mut value = body();
            value["stream"] = json!(true);
            (client.chat_request(value).unwrap(), "chat-0")
        };
        let mut response = client.send(request).await.unwrap();
        assert!(!response.body.next().await.unwrap().unwrap().is_empty());
        client.clear_response_cache().await;
        response.bytes().await.unwrap();
        assert_eq!(
            client.verify_response(id).await.unwrap_err().code(),
            "api.completion_not_found"
        );
    }
}

#[tokio::test]
async fn incognito_requires_explicitly_valid_metadata_and_rejects_model_policy() {
    let fixture = Fixture {
        metadata: Mutex::new(Some(
            json!({"metadata":{"providerType":"external","attestationSupported":false}}),
        )),
        ..Default::default()
    };
    let (_server, f, mut options) = setup(fixture).await;
    let client = InferenceClient::with_options(options.clone()).unwrap();
    assert!(client
        .verify("vendor/model")
        .await
        .unwrap()
        .models
        .is_empty());
    let c = client.chat_completions(body()).await.unwrap();
    assert_eq!(
        client
            .verify_response(c["id"].as_str().unwrap())
            .await
            .unwrap()
            .signature_kind(),
        CompletionSignatureKind::Gateway
    );
    assert_eq!(f.model.load(Ordering::SeqCst), 0);
    options.e2ee = true;
    assert_eq!(
        InferenceClient::with_options(options.clone())
            .unwrap()
            .verify("vendor/model")
            .await
            .unwrap_err()
            .code(),
        "policy.model_attestation_required"
    );
    options.e2ee = false;
    options.model_verification.policy = Some(Default::default());
    assert_eq!(
        InferenceClient::with_options(options)
            .unwrap()
            .verify("vendor/model")
            .await
            .unwrap_err()
            .code(),
        "policy.model_attestation_required"
    );
}
#[tokio::test]
async fn malformed_metadata_never_falls_back_to_incognito() {
    for metadata in [
        json!({"metadata":{}}),
        json!({"metadata":{"providerType":"vllm","attestationSupported":"true"}}),
    ] {
        let (_server, f, options) = setup(Fixture {
            metadata: Mutex::new(Some(metadata)),
            ..Default::default()
        })
        .await;
        assert!(InferenceClient::with_options(options)
            .unwrap()
            .chat_completions(body())
            .await
            .is_err());
        assert_eq!(f.chat.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn empty_reports_invalid_candidate_and_unbound_keys_block_chat() {
    for fixture in [
        Fixture {
            empty: true,
            ..Default::default()
        },
        Fixture {
            bad_model: true,
            ..Default::default()
        },
        Fixture {
            bad_key: true,
            ..Default::default()
        },
    ] {
        let (_server, f, options) = setup(fixture).await;
        assert!(InferenceClient::with_options(options)
            .unwrap()
            .chat_completions(body())
            .await
            .is_err());
        assert_eq!(f.chat.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn streaming_retains_tail_and_does_not_verify_partial_responses() {
    let (_server, _f, options) = setup(Fixture::default()).await;
    let client = InferenceClient::with_options(options).unwrap();
    let mut value = body();
    value["stream"] = json!(true);
    let request = client.chat_request(value.clone()).unwrap();
    let mut response = client.send(request).await.unwrap();
    let first = response.body.next().await.unwrap().unwrap();
    assert!(std::str::from_utf8(&first).unwrap().contains("Hello"));
    assert_eq!(
        client.verify_response("chat-0").await.unwrap_err().code(),
        "api.completion_not_found"
    );
    let rest = response.bytes().await.unwrap();
    assert!(rest.ends_with(b": tail\n\n"));
    client.verify_response("chat-0").await.unwrap();
    let mut response = client
        .send(client.chat_request(value).unwrap())
        .await
        .unwrap();
    response.body.next().await.unwrap().unwrap();
    drop(response);
    assert_eq!(
        client.verify_response("chat-1").await.unwrap_err().code(),
        "api.completion_not_found"
    );
}
#[tokio::test]
async fn compressed_chat_responses_keep_receipts() {
    for encoding in ["gzip", "br"] {
        for streaming in [false, true] {
            let (_server, _, options) = setup(Fixture {
                response_encoding: Some(encoding),
                ..Default::default()
            })
            .await;
            let client = InferenceClient::with_options(options).unwrap();
            let mut request = body();
            request["stream"] = json!(streaming);
            let response = client
                .send(client.chat_request(request).unwrap())
                .await
                .unwrap();
            assert!(!response.headers.contains_key("content-encoding"));
            assert!(!response.headers.contains_key("content-length"));
            response.bytes().await.unwrap();
            client.verify_response("chat-0").await.unwrap();
        }
    }
}

#[tokio::test]
async fn owns_authentication_and_rejects_other_endpoints() {
    let (_server, f, options) = setup(Fixture::default()).await;
    let client = InferenceClient::with_options(options).unwrap();
    let mut request = client.chat_request(body()).unwrap();
    request
        .headers_mut()
        .insert("authorization", "Bearer wrong".parse().unwrap());
    request
        .headers_mut()
        .insert("api-key", "wrong".parse().unwrap());
    request
        .headers_mut()
        .insert("x-encryption-version", "99".parse().unwrap());
    client.send(request).await.unwrap().bytes().await.unwrap();
    let mut request = client.chat_request(body()).unwrap();
    request.url_mut().set_path("/v1/responses/resp_fixture");
    assert!(client.send(request).await.is_err());
    assert_eq!(f.chat.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn retries_only_transient_receipt_failures() {
    let (_server, f, options) = setup(Fixture {
        retry_signature: true,
        ..Default::default()
    })
    .await;
    let client = InferenceClient::with_options(options).unwrap();
    client.chat_completions(body()).await.unwrap();
    assert!(client
        .verify_response("chat-0")
        .await
        .unwrap_err()
        .retryable());
    client.verify_response("chat-0").await.unwrap();
    assert_eq!(f.signatures.load(Ordering::SeqCst), 2);
    let (_server, f, options) = setup(Fixture {
        wrong_signer: true,
        ..Default::default()
    })
    .await;
    let client = InferenceClient::with_options(options).unwrap();
    client.chat_completions(body()).await.unwrap();
    for _ in 0..2 {
        assert_eq!(
            client.verify_response("chat-0").await.unwrap_err().code(),
            "signature.signer_mismatch"
        );
    }
    assert_eq!(f.signatures.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn shares_inflight_verification_and_can_disable_cache() {
    let (_server, f, mut options) = setup(Fixture::default()).await;
    let client = InferenceClient::with_options(options.clone()).unwrap();
    let (a, b) = tokio::join!(client.verify("vendor/model"), client.verify("vendor/model"));
    assert_eq!(a.unwrap().verified_at, b.unwrap().verified_at);
    assert_eq!(f.gateway.load(Ordering::SeqCst), 1);
    options.attestation_cache_ttl = Duration::ZERO;
    let client = InferenceClient::with_options(options).unwrap();
    client.verify("vendor/model").await.unwrap();
    client.verify("vendor/model").await.unwrap();
    assert_eq!(f.gateway.load(Ordering::SeqCst), 3);
}
#[tokio::test]
async fn zero_response_ttl_disables_retention() {
    let (_server, _f, mut options) = setup(Fixture::default()).await;
    options.response_cache_ttl = Duration::ZERO;
    let client = InferenceClient::with_options(options).unwrap();
    client.chat_completions(body()).await.unwrap();
    assert_eq!(
        client.verify_response("chat-0").await.unwrap_err().code(),
        "api.completion_not_found"
    );
}

#[tokio::test]
async fn canceled_verifications_keep_other_waiters_alive() {
    let (_server, f, options) = setup(Fixture::default()).await;
    let client = InferenceClient::with_options(options).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(5), client.verify("abandoned"))
            .await
            .is_err()
    );
    client.verify("vendor/model").await.unwrap();
    let (canceled, remaining) = tokio::join!(
        tokio::time::timeout(Duration::from_millis(5), client.verify("shared")),
        client.verify("shared")
    );
    assert!(canceled.is_err());
    remaining.unwrap();
    assert!((2..=3).contains(&f.gateway.load(Ordering::SeqCst)));
}
#[tokio::test]
async fn header_credentials_override_adapted_requests_and_disable_compression() {
    let (_server, _f, mut options) = setup(Fixture {
        header_auth: true,
        ..Default::default()
    })
    .await;
    options.api_key = None;
    options
        .headers
        .insert("api-key", "fixture".parse().unwrap());
    let client = InferenceClient::with_options(options).unwrap();
    let mut request = client.chat_request(body()).unwrap();
    request
        .headers_mut()
        .insert("api-key", "wrong".parse().unwrap());
    request
        .headers_mut()
        .insert("authorization", "Bearer wrong".parse().unwrap());
    request
        .headers_mut()
        .insert("accept-encoding", "gzip".parse().unwrap());
    client.send(request).await.unwrap().bytes().await.unwrap();
    client.verify_response("chat-0").await.unwrap();
}
#[tokio::test]
async fn shares_concurrent_receipt_fetches_and_retries_transient_failures() {
    let (_server, f, options) = setup(Fixture {
        retry_signature: true,
        ..Default::default()
    })
    .await;
    let client = InferenceClient::with_options(options).unwrap();
    client.chat_completions(body()).await.unwrap();
    let (a, b) = tokio::join!(
        client.verify_response("chat-0"),
        client.verify_response("chat-0")
    );
    assert!(a.unwrap_err().retryable());
    assert!(b.unwrap_err().retryable());
    assert_eq!(f.signatures.load(Ordering::SeqCst), 1);
    let (a, b) = tokio::join!(
        tokio::time::timeout(Duration::from_millis(5), client.verify_response("chat-0")),
        client.verify_response("chat-0")
    );
    assert!(a.is_err());
    b.unwrap();
    client.verify_response("chat-0").await.unwrap();
    assert_eq!(f.signatures.load(Ordering::SeqCst), 2);
    assert_eq!(f.chat.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn encrypted_json_and_sse_preserve_wire_receipts_for_both_algorithms() {
    for ecdsa in [false, true] {
        let (_server, f, mut options) = setup(Fixture {
            ecdsa,
            shared_model: true,
            extra_model: true,
            first_model_key_missing: true,
            ..Default::default()
        })
        .await;
        options.e2ee = true;
        if ecdsa {
            options.signing_algo = SigningAlgo::Ecdsa;
        }
        let client = InferenceClient::with_options(options).unwrap();
        let preflight = client.verify("vendor/model").await.unwrap();
        assert_eq!(preflight.models.len(), 4);
        assert!(preflight.models[0].signing_public_key.is_none());
        let expected = vec![preflight.models[1].clone(), preflight.models[3].clone()];
        let completion = client.chat_completions(body()).await.unwrap();
        assert_eq!(completion["choices"][0]["message"]["content"], "Hello");
        assert_eq!(
            client.verify_response("chat-0").await.unwrap().attestations,
            expected
        );
        let mut request = body();
        request["stream"] = json!(true);
        let response = client
            .send(client.chat_request(request).unwrap())
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert!(String::from_utf8(response).unwrap().contains("Hello"));
        assert_eq!(
            client.verify_response("chat-1").await.unwrap().attestations,
            expected
        );
        for (request, response, _) in f.receipts.lock().unwrap().values() {
            assert!(!String::from_utf8_lossy(request).contains("Hello"));
            assert!(!String::from_utf8_lossy(response).contains("Hello"));
        }
    }
}
#[tokio::test]
async fn integrated_ohttp_authenticates_config_and_verifies_inner_receipts() {
    for direct in [false, true] {
        for case in [
            "valid",
            "alternate_spelling",
            "missing",
            "wrong_signer",
            "bad_signature",
            "bad_config",
            "tampered_final",
        ] {
            let (server, f, mut options) = setup(Fixture {
                direct,
                ohttp: if case == "missing" {
                    None
                } else {
                    Some(ohttp_config())
                },
                wrong_ohttp_signer: case == "wrong_signer",
                bad_ohttp_signature: case == "bad_signature",
                bad_ohttp_config: case == "bad_config",
                tampered_ohttp_response: case == "tampered_final",
                alternate_direct_signer: direct && case == "alternate_spelling",
                ..Default::default()
            })
            .await;
            options.ohttp = true;
            options.e2ee = true;
            // Exercise JSON and SSE, with encryption inside the OHTTP tunnel.
            for streaming in [false, true] {
                let mut request = body();
                request["stream"] = json!(streaming);
                let (result, receipt) = if direct {
                    let client =
                        DirectInferenceClient::with_options(options.clone().into()).unwrap();
                    let result = match client.send(client.chat_request(request).unwrap()).await {
                        Ok(r) => r.bytes().await,
                        Err(e) => Err(e),
                    };
                    let receipt = if result.is_ok() {
                        Some(
                            client
                                .verify_response(&format!("chat-{}", usize::from(streaming)))
                                .await
                                .map(|receipt| receipt.attestations.len()),
                        )
                    } else {
                        assert_eq!(
                            client.verify_response("chat-0").await.unwrap_err().code(),
                            "api.completion_not_found"
                        );
                        None
                    };
                    (result, receipt)
                } else {
                    let client = InferenceClient::with_options(options.clone()).unwrap();
                    let result = match client.send(client.chat_request(request).unwrap()).await {
                        Ok(r) => r.bytes().await,
                        Err(e) => Err(e),
                    };
                    let receipt = if result.is_ok() {
                        Some(
                            client
                                .verify_response(&format!("chat-{}", usize::from(streaming)))
                                .await
                                .map(|receipt| receipt.attestations.len()),
                        )
                    } else {
                        assert_eq!(
                            client.verify_response("chat-0").await.unwrap_err().code(),
                            "api.completion_not_found"
                        );
                        None
                    };
                    (result, receipt)
                };
                if case == "valid" || case == "alternate_spelling" {
                    assert!(String::from_utf8(result.unwrap())
                        .unwrap()
                        .contains("Hello"));
                    let attestation_count = receipt.unwrap().unwrap();
                    assert_eq!(attestation_count, if direct { 2 } else { 1 });
                } else {
                    assert_eq!(
                        result.unwrap_err().code(),
                        match case {
                            "missing" => "ohttp.attestation_required",
                            "wrong_signer" => "ohttp.signer_mismatch",
                            "bad_signature" => "ohttp.signature_invalid",
                            "bad_config" => "ohttp.key_config_invalid",
                            "tampered_final" => "ohttp.decryption_failed",
                            _ => unreachable!(),
                        }
                    );
                    assert_eq!(
                        f.chat.load(Ordering::SeqCst),
                        if case == "tampered_final" {
                            1 + usize::from(streaming)
                        } else {
                            0
                        }
                    );
                    assert_eq!(f.signatures.load(Ordering::SeqCst), 0);
                    if !direct && case != "tampered_final" {
                        assert_eq!(f.model.load(Ordering::SeqCst), 0);
                        assert!(server
                            .received_requests()
                            .await
                            .unwrap()
                            .iter()
                            .all(|request| {
                                request.url.path() == "/v1/attestation/report"
                                    && !request.url.query_pairs().any(|(key, _)| key == "model")
                            }));
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn new_completions_keep_unexpired_receipts_verifiable() {
    let (_server, _, options) = setup(Fixture::default()).await;
    let client = InferenceClient::with_options(options).unwrap();
    for _ in 0..=1024 {
        client.chat_completions(body()).await.unwrap();
    }
    client.verify_response("chat-0").await.unwrap();
    client.verify_response("chat-1024").await.unwrap();
}
