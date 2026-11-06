use super::fixture::{ohttp_config, setup, Fixture};
use futures_util::StreamExt;
use nearai_inference_sdk::*;
use serde_json::{json, Value};
use std::{sync::atomic::Ordering, time::Duration};

fn message_request_body(streaming: bool) -> Value {
    json!({
        "model": "vendor/model", "max_tokens": 128, "stream": streaming,
        "messages": [
            {"role":"assistant", "content":[{"type":"tool_use", "id":"prior", "name":"weather", "input":{}}]},
            {"role":"user", "content":[{"type":"tool_result", "tool_use_id":"prior", "content":"20"}]}
        ]
    })
}

#[tokio::test]
async fn messages_json_and_sse_retain_exact_gateway_receipts() {
    for streaming in [false, true] {
        for (oblivious, ecdsa) in [(false, false), (false, true), (true, false)] {
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
            let body = message_request_body(streaming);

            if streaming {
                let response = client
                    .send(client.message_request(body).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.bytes().await.unwrap(),
                    include_bytes!("../../test-fixtures/messages/message.sse")
                );
            } else {
                let response = client.create_message(body).await.unwrap();
                assert_eq!(response["id"], "msg_fixture");
                assert_eq!(response["content"][1]["input"]["city"], "Beijing");
            }

            let receipt = client.verify_response("msg_fixture").await.unwrap();
            assert_eq!(receipt.signature_kind(), CompletionSignatureKind::Gateway);
            assert!(matches!(
                receipt.attestation,
                VerifiedCompletionAttestation::Gateway(_)
            ));
            assert_eq!(f.chat.load(Ordering::SeqCst), 1);
            assert_eq!(
                client
                    .verify_response("toolu_fixture")
                    .await
                    .unwrap_err()
                    .code(),
                "api.completion_not_found"
            );
        }
    }
}

#[tokio::test]
async fn messages_reject_tampering_and_provider_receipts() {
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
                        .message_request(message_request_body(streaming))
                        .unwrap(),
                )
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();

            assert_eq!(
                client
                    .verify_response("msg_fixture")
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
async fn messages_retry_receipts_without_repeating_inference() {
    let (_server, f, options) = setup(Fixture {
        retry_signature: true,
        ..Default::default()
    })
    .await;
    let client = InferenceClient::with_options(options).unwrap();

    client
        .create_message(message_request_body(false))
        .await
        .unwrap();

    assert_eq!(
        client
            .verify_response("msg_fixture")
            .await
            .unwrap_err()
            .code(),
        "api.http_status"
    );
    client.verify_response("msg_fixture").await.unwrap();

    assert_eq!(f.chat.load(Ordering::SeqCst), 1);
    assert_eq!(f.signatures.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn messages_missing_ids_and_http_errors_are_not_receipts() {
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
                    .message_request(message_request_body(streaming))
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
            .create_message(message_request_body(false))
            .await
            .unwrap_err()
            .code(),
        "api.http_status"
    );
    assert_eq!(
        client
            .verify_response("msg_fixture")
            .await
            .unwrap_err()
            .code(),
        "api.completion_not_found"
    );
}

#[tokio::test]
async fn messages_unsupported_modes_are_rejected_before_preflight() {
    let (_server, f, mut options) = setup(Fixture::default()).await;
    options.e2ee = true;
    let client = InferenceClient::with_options(options.clone()).unwrap();

    assert_eq!(
        client
            .create_message(message_request_body(false))
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
            .create_message(message_request_body(true))
            .await
            .unwrap_err()
            .code(),
        "api.invalid_input"
    );
    assert_eq!(
        direct
            .send(client.message_request(message_request_body(false)).unwrap())
            .await
            .err()
            .unwrap()
            .code(),
        "api.invalid_input"
    );

    let mut request = client.message_request(message_request_body(false)).unwrap();
    request.url_mut().set_path("/v1/messages/resp_fixture");

    assert_eq!(
        client.send(request).await.err().unwrap().code(),
        "api.invalid_input"
    );
    assert_eq!(f.gateway.load(Ordering::SeqCst), 0);
    assert_eq!(f.chat.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn messages_incomplete_or_failed_streams_have_no_receipt() {
    for ending in [
        "",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}",
        "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"other\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    ] {
        let raw = format!("event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_fixture\"}}}}\n\n{ending}").into_bytes();
        let (_server, f, options) = setup(Fixture { response_body: Some(raw), ..Default::default() }).await;
        let client = InferenceClient::with_options(options).unwrap();
        let response = client.send(client.message_request(message_request_body(true)).unwrap()).await.unwrap();
        assert_eq!(response.bytes().await.unwrap_err().code(), "api.invalid_response");
        assert_eq!(client.verify_response("msg_fixture").await.unwrap_err().code(), "api.completion_not_found");
        assert_eq!(f.chat.load(Ordering::SeqCst), 1);
        assert_eq!(f.signatures.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn messages_dropped_stream_has_no_receipt() {
    let (_server, f, options) = setup(Fixture::default()).await;
    let client = InferenceClient::with_options(options).unwrap();
    let mut response = client
        .send(client.message_request(message_request_body(true)).unwrap())
        .await
        .unwrap();
    response.body.next().await.unwrap().unwrap();
    drop(response);
    assert_eq!(
        client
            .verify_response("msg_fixture")
            .await
            .unwrap_err()
            .code(),
        "api.completion_not_found"
    );
    assert_eq!(f.chat.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn messages_stream_contract() {
    let cases: Value =
        serde_json::from_str(include_str!("../../test-fixtures/messages/streams.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let raw = case["body"].as_str().unwrap().as_bytes().to_vec();
        let (_server, fixture, options) = setup(Fixture {
            response_body: Some(raw.clone()),
            ..Default::default()
        })
        .await;
        let client = InferenceClient::with_options(options).unwrap();
        let response = client
            .send(client.message_request(message_request_body(true)).unwrap())
            .await
            .unwrap();
        let body = response.bytes().await;
        if case["valid"].as_bool().unwrap() {
            assert_eq!(body.unwrap(), raw, "{}", case["name"]);
            client.verify_response("msg_fixture").await.unwrap();
        } else {
            assert_eq!(
                body.unwrap_err().code(),
                "api.invalid_response",
                "{}",
                case["name"]
            );
            assert_eq!(
                client
                    .verify_response("msg_fixture")
                    .await
                    .unwrap_err()
                    .code(),
                "api.completion_not_found"
            );
            assert_eq!(fixture.signatures.load(Ordering::SeqCst), 0);
        }
        assert_eq!(fixture.chat.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn messages_duplicate_id_preserves_original_receipt() {
    for streaming in [false, true] {
        let (_server, fixture, options) = setup(Fixture::default()).await;
        let client = InferenceClient::with_options(options).unwrap();
        let request = client
            .message_request(message_request_body(streaming))
            .unwrap();

        let response = client.send(request).await.unwrap();
        response.bytes().await.unwrap();
        let receipt = client.verify_response("msg_fixture").await.unwrap();
        assert_eq!(receipt.id, "msg_fixture");

        let duplicate = client
            .message_request(message_request_body(streaming))
            .unwrap();
        let response = client.send(duplicate).await.unwrap();
        let error = response.bytes().await.unwrap_err();
        assert_eq!(error.code(), "api.duplicate_completion_id");
        assert_eq!(
            client.verify_response("msg_fixture").await.unwrap().id,
            receipt.id
        );
        assert_eq!(fixture.signatures.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.chat.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn messages_zero_response_ttl_disables_retention() {
    for streaming in [false, true] {
        let (_server, fixture, mut options) = setup(Fixture::default()).await;
        options.response_cache_ttl = Duration::ZERO;
        let client = InferenceClient::with_options(options).unwrap();

        for _ in 0..2 {
            let request = client
                .message_request(message_request_body(streaming))
                .unwrap();
            let response = client.send(request).await.unwrap();
            response.bytes().await.unwrap();

            let error = client.verify_response("msg_fixture").await.unwrap_err();
            assert_eq!(error.code(), "api.completion_not_found");
        }
        assert_eq!(fixture.signatures.load(Ordering::SeqCst), 0);
    }
}
