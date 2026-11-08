use super::fixture::{ohttp_config, response_request_body, setup, Fixture};
use nearai_inference_sdk::*;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn responses_json_and_sse_retain_exact_gateway_receipts() {
    for streaming in [false, true] {
        for (ecdsa, oblivious) in [(false, false), (true, false), (false, true)] {
            let fixture = Fixture {
                ecdsa,
                ohttp: oblivious.then(ohttp_config),
                ..Default::default()
            };
            let (_server, f, mut options) = setup(fixture).await;
            options.ohttp = oblivious;
            if ecdsa {
                options.signing_algo = SigningAlgo::Ecdsa;
            }
            let client = InferenceClient::with_options(options).unwrap();
            let body = response_request_body(streaming);

            if streaming {
                let response = client
                    .send(client.response_request(body).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.bytes().await.unwrap(),
                    include_bytes!("../fixtures/responses/response.sse")
                );
            } else {
                let response = client.create_response(body).await.unwrap();
                assert_eq!(response["id"], "resp_fixture");
                assert_eq!(
                    response["output"][2]["arguments"],
                    "{\"city\":\"UTF-8 City é € 🌍\"}"
                );
            }

            let receipt = client.verify_response("resp_fixture").await.unwrap();
            assert_eq!(receipt.signature_kind(), CompletionSignatureKind::Gateway);
            assert!(matches!(
                receipt.attestation,
                VerifiedCompletionAttestation::Gateway(_)
            ));
            assert_eq!(f.chat.load(Ordering::SeqCst), 1);
            assert_eq!(
                client.verify_response("msg_1").await.unwrap_err().code(),
                "api.completion_not_found"
            );
        }
    }
}

#[tokio::test]
async fn responses_stream_receipt() {
    let start = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_fixture\",\"status\":\"in_progress\"}}\n\n";
    for (name, ending, valid) in [
        ("completed at EOF", "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_fixture\",\"status\":\"completed\"}}\n\n", true),
        ("output limit", "event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp_fixture\",\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}\n\n", true),
        ("failed response", "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_fixture\",\"status\":\"failed\",\"error\":{\"code\":\"server_error\",\"message\":\"failed\"}}}\n\n", true),
        ("DONE with trailing bytes", "data: [DONE]\n\ndata: not-json\n\n", true),
        ("conflicting response ID", "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"other\",\"status\":\"completed\"}}\n\n", false),
        ("stream error", "event: error\ndata: {\"type\":\"error\",\"error\":{\"message\":\"failed\"}}\n\n", false),
    ] {
        let raw = format!("{start}{ending}").into_bytes();
        let (_server, f, options) = setup(Fixture {
            response_body: Some(raw.clone()),
            ..Default::default()
        })
        .await;
        let client = InferenceClient::with_options(options).unwrap();
        let result = client
            .send(
                client
                    .response_request(response_request_body(true))
                    .unwrap(),
            )
            .await
            .unwrap()
            .bytes()
            .await;
        if valid {
            assert_eq!(result.unwrap(), raw, "{name}");
            let receipt = client.verify_response("resp_fixture").await.unwrap();
            assert_eq!(receipt.signature_kind(), CompletionSignatureKind::Gateway);
            assert!(receipt.attestations.is_empty());
            assert_eq!(f.signatures.load(Ordering::SeqCst), 1, "{name}");
        } else {
            assert_eq!(result.unwrap_err().code(), "api.invalid_response", "{name}");
            assert_eq!(
                client
                    .verify_response("resp_fixture")
                    .await
                    .unwrap_err()
                    .code(),
                "api.completion_not_found",
                "{name}"
            );
            assert_eq!(f.signatures.load(Ordering::SeqCst), 0, "{name}");
        }
        for unrelated_id in ["msg_1", "event_only", "other"] {
            assert_eq!(
                client
                    .verify_response(unrelated_id)
                    .await
                    .unwrap_err()
                    .code(),
                "api.completion_not_found",
                "{name}: {unrelated_id}"
            );
        }
        assert_eq!(f.chat.load(Ordering::SeqCst), 1, "{name}");
    }
}

#[tokio::test]
async fn responses_reject_tampering_and_provider_receipts() {
    for streaming in [false, true] {
        for provider in [false, true] {
            let (_server, _f, options) = setup(Fixture {
                response_tamper: !provider,
                response_provider_receipt: provider,
                ..Default::default()
            })
            .await;
            let client = InferenceClient::with_options(options).unwrap();

            client
                .send(
                    client
                        .response_request(response_request_body(streaming))
                        .unwrap(),
                )
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();

            assert_eq!(
                client
                    .verify_response("resp_fixture")
                    .await
                    .unwrap_err()
                    .code(),
                if provider {
                    "signature.kind_mismatch"
                } else {
                    "signature.payload_mismatch"
                }
            );
        }
    }
}

#[tokio::test]
async fn responses_retry_receipts_without_repeating_inference() {
    let (_server, f, options) = setup(Fixture {
        retry_signature: true,
        ..Default::default()
    })
    .await;
    let client = InferenceClient::with_options(options).unwrap();

    client
        .create_response(response_request_body(false))
        .await
        .unwrap();

    assert_eq!(
        client
            .verify_response("resp_fixture")
            .await
            .unwrap_err()
            .code(),
        "api.http_status"
    );
    client.verify_response("resp_fixture").await.unwrap();

    assert_eq!(f.chat.load(Ordering::SeqCst), 1);
    assert_eq!(f.signatures.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn responses_missing_ids_and_http_errors_are_not_receipts() {
    for streaming in [false, true] {
        let raw = if streaming {
            b"data: {\"id\":\"item-only\",\"item\":{\"id\":\"msg_1\"}}\n\n".to_vec()
        } else {
            b"{\"output\":[]}".to_vec()
        };
        let (_server, _f, options) = setup(Fixture {
            response_body: Some(raw),
            ..Default::default()
        })
        .await;
        let client = InferenceClient::with_options(options).unwrap();

        let result = client
            .send(
                client
                    .response_request(response_request_body(streaming))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            result.bytes().await.unwrap_err().code(),
            "api.invalid_response"
        );
    }

    let (_server, _f, options) = setup(Fixture {
        response_status: Some(400),
        ..Default::default()
    })
    .await;
    let client = InferenceClient::with_options(options).unwrap();

    assert_eq!(
        client
            .create_response(response_request_body(false))
            .await
            .unwrap_err()
            .code(),
        "api.http_status"
    );
    assert_eq!(
        client
            .verify_response("resp_fixture")
            .await
            .unwrap_err()
            .code(),
        "api.completion_not_found"
    );
}

#[tokio::test]
async fn responses_unsupported_modes_are_rejected_before_preflight() {
    let (_server, f, mut options) = setup(Fixture::default()).await;
    options.e2ee = true;
    let client = InferenceClient::with_options(options.clone()).unwrap();

    assert_eq!(
        client
            .create_response(response_request_body(false))
            .await
            .unwrap_err()
            .code(),
        "api.invalid_input"
    );

    options.e2ee = false;
    let direct =
        DirectInferenceClient::with_options(super::fixture::direct_options(options.clone()))
            .unwrap();
    let client = InferenceClient::with_options(options).unwrap();

    assert_eq!(
        client
            .create_response(response_request_body(true))
            .await
            .unwrap_err()
            .code(),
        "api.invalid_input"
    );
    assert_eq!(
        direct
            .send(
                client
                    .response_request(response_request_body(false))
                    .unwrap()
            )
            .await
            .err()
            .unwrap()
            .code(),
        "api.invalid_input"
    );

    let mut request = client
        .response_request(response_request_body(false))
        .unwrap();
    request.url_mut().set_path("/v1/responses/resp_fixture");

    assert_eq!(
        client.send(request).await.err().unwrap().code(),
        "api.invalid_input"
    );
    assert_eq!(f.gateway.load(Ordering::SeqCst), 0);
    assert_eq!(f.chat.load(Ordering::SeqCst), 0);
}
