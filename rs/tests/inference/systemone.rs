use super::fixture::{body, setup, systemone_request, Fixture};
use nearai_inference_sdk::*;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn systemone_plaintext_key_routing_and_receipts() {
    for gateway_only in [false, true] {
        for ecdsa in [false, true] {
            let fixture = Fixture {
                ecdsa,
                systemone_id: Some("decision/with % space".into()),
                ..Default::default()
            };
            if gateway_only {
                *fixture.metadata.lock().unwrap() = Some(json!({
                    "metadata": {
                        "providerType": "proxy",
                        "attestationSupported": false
                    }
                }));
            }
            let (_server, f, mut options) = setup(fixture).await;
            if ecdsa {
                options.signing_algo = SigningAlgo::Ecdsa;
            }
            let client = InferenceClient::with_options(options).unwrap();
            let mut headers = reqwest::header::HeaderMap::new();
            for (k, v) in [
                ("authorization", "Bearer bad"),
                ("api-key", "bad"),
                ("accept-encoding", "gzip"),
                ("content-encoding", "gzip"),
                ("x-model-pub-key", "bad"),
                ("digest", "bad"),
            ] {
                headers.insert(k, v.parse().unwrap());
            }

            let mut result = client
                .systemone_create_with_headers(&systemone_request(), headers)
                .await
                .unwrap();

            assert_eq!(result.decision_id, "decision/with % space");
            assert!(result.data.id.is_none());

            result.data.model = "mutated".into();

            let receipt = client.verify_response(&result.decision_id).await.unwrap();
            assert_eq!(
                receipt.signature_kind(),
                if gateway_only {
                    CompletionSignatureKind::Gateway
                } else {
                    CompletionSignatureKind::ProviderTee
                }
            );

            client.verify_response(&result.decision_id).await.unwrap();
            assert_eq!(f.signatures.load(Ordering::SeqCst), 1);
            assert_eq!(f.systemone.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn systemone_preserves_json_images_and_box_receipts() {
    let image = json!({"type": "image_url", "image_url": {"url": "data:image/png;base64,ZmFrZS1pbWFnZQ=="}});
    let request_json = json!({
        "model": "vendor/model",
        "state": {"canvas": image},
        "questions": {
            "region": {"type": "box", "instructions": ["Locate the rectangle", image]},
            "present": {"type": "noul", "instructions": "Does the canvas match?", "criteria": {"true": image}}
        }
    });
    for (ecdsa, assets) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut expected = request_json.clone();
        if assets {
            expected["assets"] =
                json!({"<photo>": {"format": "png", "data_base64": "ZmFrZS1pbWFnZQ=="}});
            expected["state"] = json!({"canvas": ["<photo>", image]});
            expected["questions"]["region"]["instructions"] = json!("Locate <photo> now");
            expected["questions"]["present"]["criteria"] = json!({"true": "<photo>"});
        }
        let request: SystemOneRequest = serde_json::from_value(expected.clone()).unwrap();
        let fixture = Fixture {
            ecdsa,
            ..Default::default()
        };
        *fixture.metadata.lock().unwrap() = Some(json!({
            "metadata": {"providerType": "proxy", "attestationSupported": false}
        }));
        let (_server, f, mut options) = setup(fixture).await;
        if ecdsa {
            options.signing_algo = SigningAlgo::Ecdsa;
        }
        let client = InferenceClient::with_options(options).unwrap();
        let mut result = client.systemone_create(&request).await.unwrap();
        let SystemOneAnswer::Box {
            bounds, confidence, ..
        } = result.data.answers.get_mut("region").unwrap()
        else {
            panic!("expected box");
        };
        assert_eq!(bounds.top, 0.31);
        assert_eq!(*confidence, Some(0.82));
        bounds.top = 0.0;
        let receipt = client.verify_response(&result.decision_id).await.unwrap();
        assert_eq!(receipt.signature_kind(), CompletionSignatureKind::Gateway);
        let receipts = f.receipts.lock().unwrap();
        let (sent, _, _) = receipts.values().next().unwrap();
        assert_eq!(serde_json::from_slice::<Value>(sent).unwrap(), expected);
        assert_eq!(f.systemone.load(Ordering::SeqCst), 1);
        assert_eq!(f.signatures.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn systemone_compressed_responses() {
    for encoding in ["gzip", "br"] {
        for mode in ["receipt", "tamper", "padded"] {
            let (_server, f, options) = setup(Fixture {
                response_encoding: Some(encoding),
                systemone_tamper: mode == "tamper",
                systemone_body: (mode == "padded").then(|| {
                    let fixture: Value = serde_json::from_str(include_str!(
                        "../../test-fixtures/systemone-responses.json"
                    ))
                    .unwrap();
                    format!("{}{}", fixture["valid"][0], " ".repeat(4096))
                }),
                ..Default::default()
            })
            .await;
            let client = InferenceClient::with_options(options).unwrap();
            let result = client.systemone_create(&systemone_request()).await;
            let receipt = client.verify_response(&result.unwrap().decision_id).await;
            if mode == "tamper" {
                assert_eq!(receipt.unwrap_err().code(), "signature.payload_mismatch");
            } else {
                receipt.unwrap();
            }
            assert_eq!(f.systemone.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn systemone_shares_chat_session() {
    for decision_first in [false, true] {
        let (_server, f, options) = setup(Fixture::default()).await;
        let client = InferenceClient::with_options(options).unwrap();

        for decision in [decision_first, !decision_first] {
            if decision {
                client.systemone_create(&systemone_request()).await.unwrap();
            } else {
                client.chat_completions(body()).await.unwrap();
            }
        }

        assert_eq!(f.gateway.load(Ordering::SeqCst), 1);
        assert_eq!(f.model.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn systemone_requires_model_public_key_before_send() {
    let (_server, f, options) = setup(Fixture {
        missing_model_key: true,
        ..Default::default()
    })
    .await;
    let client = InferenceClient::with_options(options).unwrap();

    assert!(client.systemone_create(&systemone_request()).await.is_err());
    assert_eq!(f.systemone.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn systemone_preserves_structured_legend_numbers_and_receipt_bytes() {
    for (number, canonical) in [
        ("18446744073709551616", "18446744073709551616"),
        ("-18446744073709551617", "-18446744073709551617"),
        (
            "0.12345678901234567890123456789",
            "0.12345678901234567890123456789",
        ),
        ("1e400", "1e+400"),
        ("-0.0", "-0.0"),
    ] {
        for gateway_only in [false, true] {
            let response = format!(
                r#" {{"model":"vendor/model","answers":{{"q":{{"type":"score","score":0.5,"confidence":0.75,"probabilities":{{"0":0.5}},"legend":{{"0":{{"value":{number},"nested":[{number},{{"value":{number}}}]}},"1":[{number},{{"value":{number}}}]}}}}}},"usage":{{"input_tokens":1,"output_tokens":1}}}} "#
            );
            let fixture = Fixture {
                systemone_body: Some(response),
                ..Default::default()
            };
            if gateway_only {
                *fixture.metadata.lock().unwrap() = Some(json!({
                    "metadata": {
                        "providerType": "proxy",
                        "attestationSupported": false
                    }
                }));
            }
            let (_server, f, options) = setup(fixture).await;
            let client = InferenceClient::with_options(options).unwrap();

            let result = client.systemone_create(&systemone_request()).await.unwrap();
            let value = serde_json::to_value(&result.data).unwrap();
            let legend = &value["answers"]["q"]["legend"];
            for value in [
                &legend["0"]["value"],
                &legend["0"]["nested"][0],
                &legend["0"]["nested"][1]["value"],
                &legend["1"][0],
                &legend["1"][1]["value"],
            ] {
                assert!(value.is_number());
                assert_eq!(value.to_string(), canonical);
            }

            let encoded = serde_json::to_vec(&result.data).unwrap();
            let decoded: SystemOneResponse = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);

            client.verify_response(&result.decision_id).await.unwrap();
            assert_eq!(f.systemone.load(Ordering::SeqCst), 1);
            assert_eq!(f.signatures.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn systemone_rejects_bad_evidence_unsupported_modes_and_stream_before_send() {
    for mode in 0..4 {
        let (_server, f, mut options) = setup(Fixture {
            bad_model: mode == 3,
            ..Default::default()
        })
        .await;
        options.e2ee = mode == 0;
        options.ohttp = mode == 1;
        let client = InferenceClient::with_options(options).unwrap();
        let mut request = systemone_request();
        if mode == 2 {
            request["stream"] = json!(false);
        }

        assert!(client.systemone_create(&request).await.is_err());
        assert_eq!(f.systemone.load(Ordering::SeqCst), 0);
        if mode < 3 {
            assert_eq!(f.gateway.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn systemone_transport_failure_does_not_suggest_replay() {
    for reason in [
        ApiTransportReason::Request,
        ApiTransportReason::ResponseBody,
    ] {
        let error = ApiError::Transport {
            resource: ApiResource::SystemOne,
            reason,
        };
        assert_eq!(error.code(), "api.transport_failed");
        assert!(!error.retryable());
        assert!(ApiError::Transport {
            resource: ApiResource::CompletionSignature,
            reason
        }
        .retryable());
    }
}

#[tokio::test]
async fn systemone_errors_do_not_retry_or_cache_unusable_responses() {
    for fixture in [
        Fixture {
            systemone_status: Some(429),
            ..Default::default()
        },
        Fixture {
            systemone_status: Some(503),
            ..Default::default()
        },
        Fixture {
            systemone_body: Some("{}".into()),
            ..Default::default()
        },
        Fixture {
            systemone_id: Some(String::new()),
            ..Default::default()
        },
    ] {
        let (_server, f, options) = setup(fixture).await;
        let client = InferenceClient::with_options(options).unwrap();

        let error = client
            .systemone_create(&systemone_request())
            .await
            .unwrap_err();

        assert!(
            !error.retryable(),
            "inference failure must not suggest replay: {error}"
        );
        assert_eq!(f.systemone.load(Ordering::SeqCst), 1);
        assert_eq!(
            client
                .verify_response("decision-0")
                .await
                .unwrap_err()
                .code(),
            "api.completion_not_found"
        );
    }
}

#[tokio::test]
async fn systemone_rejects_wire_tampering_and_wrong_signers() {
    for fixture in [
        Fixture {
            extra_model: true,
            ..Default::default()
        },
        Fixture {
            systemone_tamper: true,
            ..Default::default()
        },
        Fixture {
            wrong_signer: true,
            ..Default::default()
        },
        Fixture {
            wrong_algo: true,
            ..Default::default()
        },
    ] {
        let (_server, _, options) = setup(fixture).await;
        let client = InferenceClient::with_options(options).unwrap();
        let result = client.systemone_create(&systemone_request()).await.unwrap();

        assert!(client.verify_response(&result.decision_id).await.is_err());
    }
}
