#[path = "support/encryption.rs"]
mod encryption;
mod support;
use async_trait::async_trait;
use ed25519_dalek::Signer;
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use futures_util::StreamExt;
use nearai_inference_sdk::*;
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use support::{model_quote, sha256_hex, APP_COMPOSE};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

struct Quote;
#[async_trait]
impl TdxQuoteVerifier for Quote {
    async fn verify(&self, quote: &str) -> Result<TdxQuoteVerificationResult, VerificationError> {
        let mut result = model_quote(TcbStatus::UpToDate);
        result.report_data = hex::decode(quote).unwrap();
        Ok(result)
    }
}
type ReceiptBytes = (Vec<u8>, Vec<u8>, String);
#[derive(Default)]
struct Fixture {
    response_encoding: Option<&'static str>,
    gateway: AtomicUsize,
    model: AtomicUsize,
    chat: AtomicUsize,
    systemone: AtomicUsize,
    systemone_body: Option<String>,
    systemone_id: Option<String>,
    systemone_status: Option<u16>,
    missing_model_key: bool,
    extra_model: bool,
    systemone_tamper: bool,

    signatures: AtomicUsize,
    signature_started: tokio::sync::Notify,
    receipts: Mutex<std::collections::HashMap<String, ReceiptBytes>>,
    metadata: Mutex<Option<Value>>,
    empty: bool,
    bad_key: bool,
    bad_model: bool,
    retry_signature: bool,
    wrong_signer: bool,
    wrong_algo: bool,
    direct: bool,
    header_auth: bool,
    ecdsa: bool,
    ohttp: Option<ohttp::KeyConfig>,
    wrong_ohttp_signer: bool,
    alternate_direct_signer: bool,
    response_body: Option<Vec<u8>>,
    response_provider_receipt: bool,
    response_tamper: bool,
    response_status: Option<u16>,
}
fn key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}
fn report(nonce: &str, seed: u8) -> Value {
    let public = hex::encode(key(seed).verifying_key().as_bytes());
    let report_data = format!("{public}{nonce}");
    json!({"request_nonce":nonce,"signing_algo":"ed25519","signing_address":public,"signing_public_key":public,"intel_quote":report_data,"report_data":report_data,"event_log":[{"digest":"00".repeat(48),"imr":3}],"info":{"tcb_info":{"app_compose":APP_COMPOSE}},"model_name":"vendor/model"})
}
impl Fixture {
    fn response(&self, mut response: ResponseTemplate, mut body: Vec<u8>) -> ResponseTemplate {
        if let Some(encoding) = self.response_encoding {
            body = match encoding {
                "gzip" => {
                    let mut encoder =
                        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                    std::io::Write::write_all(&mut encoder, &body).unwrap();
                    encoder.finish().unwrap()
                }
                "br" => {
                    let mut encoded = Vec::new();
                    brotli::BrotliCompress(&mut body.as_slice(), &mut encoded, &Default::default())
                        .unwrap();
                    encoded
                }
                _ => unreachable!(),
            };
            response = response.insert_header("content-encoding", encoding);
        }
        response.set_body_bytes(body)
    }

    fn report(&self, nonce: &str, seed: u8) -> Value {
        let mut value = report(nonce, seed);
        if self.ecdsa {
            let (address, public) = encryption::ecdsa_identity(seed);
            let data = format!("{address}{}{nonce}", "00".repeat(12));
            value["signing_algo"] = json!("ecdsa");
            value["signing_address"] = json!(address);
            value["signing_public_key"] = json!(public);
            value["report_data"] = json!(data);
            value["intel_quote"] = json!(data);
        }
        if self.missing_model_key && seed != 9 {
            value.as_object_mut().unwrap().remove("signing_public_key");
        }
        value
    }
    fn with_ohttp(&self, mut value: Value) -> Value {
        if let Some(config) = &self.ohttp {
            let bytes = config.encode().unwrap();
            let signer = key(if self.wrong_ohttp_signer {
                8
            } else if self.direct {
                7
            } else {
                9
            });
            value["ohttp_attestation"] = json!({"signing_algo":"ed25519","signing_key":hex::encode(signer.verifying_key().as_bytes()),"key_config":hex::encode(&bytes),"signature":hex::encode(signer.sign(&bytes).to_bytes())});
        }
        value
    }
}
impl Respond for Fixture {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        if self.header_auth {
            assert_eq!(r.headers.get("api-key").unwrap(), "fixture");
            assert!(r.headers.get("authorization").is_none());
        } else {
            assert_eq!(r.headers.get("authorization").unwrap(), "Bearer fixture");
        }
        assert_eq!(r.headers.get("x-test").unwrap(), "custom");
        match r.url.path() {
            path if path.starts_with("/v1/model/") => ResponseTemplate::new(200).set_body_json(
                self.metadata.lock().unwrap().clone().unwrap_or(
                    json!({"metadata":{"providerType":"vllm","attestationSupported":true}}),
                ),
            ),
            "/v1/attestation/report" => {
                let q: std::collections::HashMap<_, _> = r.url.query_pairs().collect();
                let nonce = &q["nonce"];
                assert_eq!(q["include_tls_fingerprint"], "false");
                if self.direct {
                    self.model.fetch_add(1, Ordering::SeqCst);
                    let mut root = self.report(nonce, 7);
                    root["info"]["instance_id"] = json!("serving");
                    if self.alternate_direct_signer {
                        root.as_object_mut().unwrap().remove("signing_public_key");
                    }
                    let mut value = root.clone();
                    let mut other = self.report(nonce, 7);
                    other["info"]["instance_id"] = json!("other");
                    if self.alternate_direct_signer {
                        other["signing_address"] = json!(format!(
                            "0X{}",
                            other["signing_address"].as_str().unwrap().to_uppercase()
                        ));
                    }
                    if self.bad_model {
                        other["report_data"] = json!("ff".repeat(64));
                    }
                    value["all_attestations"] = json!([root, other]);
                    return ResponseTemplate::new(200).set_body_json(self.with_ohttp(value));
                }
                if q.contains_key("model") {
                    self.model.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(r.headers.get("x-no-aliasing").unwrap(), "true");
                    let mut value = self.report(nonce, 7);
                    if self.bad_key {
                        value["signing_public_key"] =
                            json!(hex::encode(key(8).verifying_key().as_bytes()));
                    }
                    let mut reports = vec![value];
                    if self.extra_model {
                        reports.insert(0, self.report(nonce, 8));
                    }
                    if self.bad_model {
                        let mut bad = self.report(nonce, 8);
                        bad["report_data"] = json!("ff".repeat(64));
                        reports.push(bad);
                    }
                    ResponseTemplate::new(200).set_body_json(
                        json!({"model_attestations":if self.empty {vec![]} else {reports}}),
                    )
                } else {
                    self.gateway.fetch_add(1, Ordering::SeqCst);
                    ResponseTemplate::new(200)
                        .set_body_json(
                            self.with_ohttp(json!({"gateway_attestation":self.report(nonce,9)})),
                        )
                        .set_delay(Duration::from_millis(20))
                }
            }
            "/v1/systemone" => {
                let n = self.systemone.fetch_add(1, Ordering::SeqCst);
                assert_eq!(r.headers.get("accept-encoding").unwrap(), "identity");
                assert_eq!(r.headers.get("x-no-aliasing").unwrap(), "true");
                if self.metadata.lock().unwrap().is_none() {
                    let seed = if self.extra_model { 8 } else { 7 };
                    let public = if self.ecdsa {
                        encryption::ecdsa_identity(seed).1
                    } else {
                        hex::encode(key(seed).verifying_key().as_bytes())
                    };
                    assert_eq!(r.headers.get("x-model-pub-key").unwrap(), public.as_str());
                } else {
                    assert!(r.headers.get("x-model-pub-key").is_none());
                }
                for name in [
                    "x-client-pub-key",
                    "x-signing-algo",
                    "digest",
                    "content-encoding",
                ] {
                    assert!(r.headers.get(name).is_none(), "unexpected {name}");
                }
                if let Some(status) = self.systemone_status {
                    return ResponseTemplate::new(status);
                }
                let id = self
                    .systemone_id
                    .clone()
                    .unwrap_or_else(|| format!("decision-{n}"));
                let response = self
                    .systemone_body
                    .clone()
                    .unwrap_or_else(|| {
                        let v: Value = serde_json::from_str(include_str!(
                            "../test-fixtures/systemone-responses.json"
                        ))
                        .unwrap();
                        format!(" \n{} \n", v["valid"][0])
                    })
                    .into_bytes();
                let kind = if self.metadata.lock().unwrap().is_some() {
                    "gateway"
                } else {
                    "provider_tee"
                };
                let mut encoded = reqwest::Url::parse("http://localhost/").unwrap();
                encoded.path_segments_mut().unwrap().push(&id);
                self.receipts.lock().unwrap().insert(
                    encoded.path()[1..].into(),
                    (r.body.clone(), response.clone(), kind.into()),
                );
                let mut wire = response;
                if self.systemone_tamper {
                    wire.push(b' ');
                }
                self.response(
                    ResponseTemplate::new(200).insert_header("x-generation-id", id),
                    wire,
                )
            }
            "/v1/responses" => {
                self.chat.fetch_add(1, Ordering::SeqCst);
                assert!(self.gateway.load(Ordering::SeqCst) > 0);
                assert_eq!(r.headers.get("x-no-aliasing").unwrap(), "true");
                assert!(r.headers.get("x-client-pub-key").is_none());
                let request: Value = serde_json::from_slice(&r.body).unwrap();
                assert_eq!(request["input"][1]["type"], "function_call_output");
                let streaming = request["stream"] == true;
                let raw = self.response_body.clone().unwrap_or_else(|| {
                    if streaming {
                        include_bytes!("../test-fixtures/responses/response.sse").to_vec()
                    } else {
                        include_bytes!("../test-fixtures/responses/response.json").to_vec()
                    }
                });
                self.receipts.lock().unwrap().insert(
                    "resp_fixture".into(),
                    (
                        r.body.clone(),
                        raw.clone(),
                        if self.response_provider_receipt {
                            "provider_tee"
                        } else {
                            "gateway"
                        }
                        .into(),
                    ),
                );
                let visible = if self.response_tamper {
                    String::from_utf8(raw)
                        .unwrap()
                        .replace("你好", "篡改")
                        .into_bytes()
                } else {
                    raw
                };
                ResponseTemplate::new(self.response_status.unwrap_or(200))
                    .insert_header(
                        "content-type",
                        if streaming {
                            "text/event-stream"
                        } else {
                            "application/json"
                        },
                    )
                    .set_body_bytes(visible)
            }
            "/v1/chat/completions" => {
                let n = self.chat.fetch_add(1, Ordering::SeqCst);
                assert_eq!(r.headers.get("x-no-aliasing").unwrap(), "true");
                assert_eq!(r.headers.get("accept-encoding").unwrap(), "identity");
                if !self.header_auth {
                    assert!(r.headers.get("api-key").is_none());
                }
                let body: Value = serde_json::from_slice(&r.body).unwrap();
                let content = if let Some(public) = r.headers.get("x-client-pub-key") {
                    let algo = if self.ecdsa {
                        SigningAlgo::Ecdsa
                    } else {
                        SigningAlgo::Ed25519
                    };
                    assert_eq!(
                        encryption::decrypt_request(
                            body["messages"][0]["content"].as_str().unwrap(),
                            algo
                        ),
                        "Hello"
                    );
                    assert_eq!(r.headers.get("x-encrypt-all-fields").unwrap(), "true");
                    encryption::encrypt_response(public.to_str().unwrap(), algo)
                } else {
                    "Hello".into()
                };
                let id = format!("chat-{n}");
                let response = if body["stream"] == true {
                    format!(
                        "event: message\r\ndata: {}\r\n\r\ndata: [DONE]\n\n: tail\n\n",
                        json!({"id":id,"choices":[{"delta":{"content":content}}]})
                    )
                    .into_bytes()
                } else {
                    json!({"id":id,"choices":[{"message":{"content":content}}]})
                        .to_string()
                        .into_bytes()
                };
                let kind = if self.metadata.lock().unwrap().is_some() {
                    "gateway"
                } else {
                    "provider_tee"
                };
                self.receipts
                    .lock()
                    .unwrap()
                    .insert(id, (r.body.clone(), response.clone(), kind.into()));
                self.response(
                    ResponseTemplate::new(200).insert_header(
                        "content-type",
                        if body["stream"] == true {
                            "text/event-stream"
                        } else {
                            "application/json"
                        },
                    ),
                    response,
                )
            }
            path if path.starts_with("/v1/signature/") => {
                let n = self.signatures.fetch_add(1, Ordering::SeqCst);
                if self.retry_signature && n == 0 {
                    return ResponseTemplate::new(404).set_delay(Duration::from_millis(20));
                }
                self.signature_started.notify_one();
                let receipts = self.receipts.lock().unwrap();
                let (req, res, kind) = receipts.get(path.rsplit('/').next().unwrap()).unwrap();
                let text = if kind == "gateway" {
                    format!("{}:{}", sha256_hex(req), sha256_hex(res))
                } else {
                    format!("vendor/model:{}:{}", sha256_hex(req), sha256_hex(res))
                };
                let signer = key(if self.wrong_signer {
                    8
                } else if kind == "gateway" {
                    9
                } else {
                    7
                });
                let mut value = json!({"text":text,"signature":hex::encode(signer.sign(text.as_bytes()).to_bytes()),"signing_address":hex::encode(signer.verifying_key().as_bytes()),"signing_algo":"ed25519"});
                if self.ecdsa {
                    let seed = if kind == "gateway" { 9 } else { 7 };
                    value["signing_algo"] = json!("ecdsa");
                    value["signing_address"] = json!(encryption::ecdsa_identity(seed).0);
                    value["signature"] = json!(encryption::ecdsa_signature(&text, seed));
                }
                if !self.direct {
                    value["signature_kind"] = json!(kind);
                }
                if self.wrong_algo {
                    value["signing_algo"] = json!("ecdsa");
                    value["signing_address"] = json!("00".repeat(20));
                }
                ResponseTemplate::new(200)
                    .set_body_json(value)
                    .set_delay(Duration::from_millis(20))
            }
            "/ohttp" => futures::executor::block_on(async {
                let server = ohttp::Server::new(self.ohttp.clone().unwrap()).unwrap();
                let mut incoming = server.decapsulate_stream(r.body.as_slice());
                let mut decoded = Vec::new();
                incoming.read_to_end(&mut decoded).await.unwrap();
                let message =
                    bhttp::Message::read_bhttp(&mut std::io::Cursor::new(decoded)).unwrap();
                let mut inner = r.clone();
                inner
                    .url
                    .set_path(std::str::from_utf8(message.control().path().unwrap()).unwrap());
                inner.headers.clear();
                for field in message.header().iter() {
                    inner.headers.append(
                        reqwest::header::HeaderName::from_bytes(field.name()).unwrap(),
                        reqwest::header::HeaderValue::from_bytes(field.value()).unwrap(),
                    );
                }
                inner.body = message.content().to_vec();
                let id = if inner.url.path() == "/v1/responses" {
                    "resp_fixture".into()
                } else {
                    format!("chat-{}", self.chat.load(Ordering::SeqCst))
                };
                self.respond(&inner);
                let body = self.receipts.lock().unwrap()[&id].1.clone();
                let mut response = bhttp::Message::response(bhttp::StatusCode::OK);
                response.put_header(
                    b"content-type".to_vec(),
                    if body.starts_with(b"event:") || body.starts_with(b":") {
                        b"text/event-stream".to_vec()
                    } else {
                        b"application/json".to_vec()
                    },
                );
                response.write_content(&body);
                let mut plain = Vec::new();
                response
                    .write_bhttp(bhttp::Mode::KnownLength, &mut plain)
                    .unwrap();
                let mut encrypted = Vec::new();
                let mut writer = incoming.response(&mut encrypted).unwrap();
                writer.write_all(&plain).await.unwrap();
                writer.close().await.unwrap();
                drop(writer);
                ResponseTemplate::new(200)
                    .insert_header("content-type", "message/ohttp-chunked-res")
                    .set_body_bytes(encrypted)
            }),
            _ => panic!("unexpected request: {}", r.url),
        }
    }
}
struct Shared(Arc<Fixture>);
impl Respond for Shared {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        self.0.respond(r)
    }
}
async fn setup(fixture: Fixture) -> (MockServer, Arc<Fixture>, InferenceClientOptions) {
    let server = MockServer::start().await;
    let fixture = Arc::new(fixture);
    Mock::given(wiremock::matchers::any())
        .respond_with(Shared(fixture.clone()))
        .mount(&server)
        .await;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-test", "custom".parse().unwrap());
    let options = InferenceClientOptions {
        api_key: Some("fixture".into()),
        base_url: format!("{}/v1", server.uri()),
        headers,
        gateway_verification: GatewayVerificationOptions {
            include_spki_fingerprint: false,
            tdx_quote: Some(Arc::new(Quote)),
            ..Default::default()
        },
        model_verification: ModelVerificationOptions {
            tdx_quote: Some(Arc::new(Quote)),
            ..Default::default()
        },
        ..Default::default()
    };
    (server, fixture, options)
}
fn body() -> Value {
    json!({"model":"vendor/model","messages":[{"role":"user","content":"Hello"}]})
}
struct DeploymentCheck(Arc<AtomicUsize>);
#[async_trait]
impl DeploymentVerifier for DeploymentCheck {
    async fn verify(&self, _: &MeasuredDeployment) -> Result<(), VerificationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[tokio::test]
async fn direct_deployment_verifier_checks_every_report() {
    let (_server, _fixture, mut options) = setup(Fixture {
        direct: true,
        ..Default::default()
    })
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    options.model_verification.deployment = Some(Arc::new(DeploymentCheck(calls.clone())));
    let client = DirectInferenceClient::with_options(options.into()).unwrap();
    let verified = client.verify("vendor/model").await.unwrap();
    assert_eq!(verified.attestations.len(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    client.chat_completions(body()).await.unwrap();
    match client.verify_response("chat-0").await.unwrap().attestation {
        VerifiedCompletionAttestation::Direct(reports) => {
            assert_eq!(reports.len(), 2);
            assert!(reports
                .iter()
                .all(|report| report.attestation.evidence.deployment_provenance
                    == DeploymentProvenanceStatus::Verified));
        }
        _ => panic!("expected direct receipt"),
    }
}

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
async fn bounded_response_capture_and_expiry_fail_closed() {
    let (_server, _f, mut options) = setup(Fixture::default()).await;
    options.max_response_bytes = 5;
    let client = InferenceClient::with_options(options.clone()).unwrap();
    assert!(client.chat_completions(body()).await.is_err());
    assert_eq!(
        client.verify_response("chat-0").await.unwrap_err().code(),
        "api.completion_not_found"
    );
    options.max_response_bytes = 1024;
    options.response_cache_ttl = Duration::ZERO;
    let client = InferenceClient::with_options(options).unwrap();
    client.chat_completions(body()).await.unwrap();
    assert_eq!(
        client.verify_response("chat-1").await.unwrap_err().code(),
        "api.completion_not_found"
    );
}
#[tokio::test]
async fn direct_client_verifies_entire_report_set_and_default_signature_kind() {
    let (_server, f, options) = setup(Fixture {
        direct: true,
        ..Default::default()
    })
    .await;
    let client = DirectInferenceClient::with_options(DirectInferenceClientOptions {
        api_key: options.api_key,
        base_url: options.base_url,
        headers: options.headers,
        model_verification: options.model_verification,
        ..Default::default()
    })
    .unwrap();
    let verified = client.verify("vendor/model").await.unwrap();
    assert_eq!(verified.attestations.len(), 2);
    assert_eq!(verified.tls_binding, GatewayTlsBinding::None);
    client.chat_completions(body()).await.unwrap();
    let receipt = client.verify_response("chat-0").await.unwrap();
    match receipt.attestation {
        VerifiedCompletionAttestation::Direct(reports) => assert_eq!(reports.len(), 2),
        _ => panic!("expected direct reports"),
    };
    assert_eq!(f.gateway.load(Ordering::SeqCst), 0);
    let receipts = f.receipts.lock().unwrap();
    let request: Value = serde_json::from_slice(&receipts["chat-0"].0).unwrap();
    assert_eq!(request["messages"][0]["content"], "Hello");
}

#[tokio::test]
async fn canceled_verifications_release_capacity_and_keep_other_waiters_alive() {
    let (_server, f, mut options) = setup(Fixture::default()).await;
    options.max_cache_entries = 1;
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
async fn direct_rejects_invalid_nonserving_report_before_chat() {
    let (_server, f, options) = setup(Fixture {
        direct: true,
        bad_model: true,
        ..Default::default()
    })
    .await;
    let client = DirectInferenceClient::with_options(options.into()).unwrap();
    assert!(client.chat_completions(body()).await.is_err());
    assert_eq!(f.chat.load(Ordering::SeqCst), 0);
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
        client.verify_response("chat-0"),
        client.verify_response("chat-0")
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(f.signatures.load(Ordering::SeqCst), 2);
}

fn ohttp_config() -> ohttp::KeyConfig {
    ohttp::KeyConfig::new(
        1,
        ohttp::hpke::Kem::X25519Sha256,
        vec![ohttp::SymmetricSuite::new(
            ohttp::hpke::Kdf::HkdfSha256,
            ohttp::hpke::Aead::Aes128Gcm,
        )],
    )
    .unwrap()
}
#[tokio::test]
async fn encrypted_json_and_sse_preserve_wire_receipts_for_both_algorithms() {
    for ecdsa in [false, true] {
        let (_server, f, mut options) = setup(Fixture {
            ecdsa,
            ..Default::default()
        })
        .await;
        options.e2ee = true;
        if ecdsa {
            options.signing_algo = SigningAlgo::Ecdsa;
        }
        let client = InferenceClient::with_options(options).unwrap();
        let completion = client.chat_completions(body()).await.unwrap();
        assert_eq!(completion["choices"][0]["message"]["content"], "Hello");
        client.verify_response("chat-0").await.unwrap();
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
        client.verify_response("chat-1").await.unwrap();
        for (request, response, _) in f.receipts.lock().unwrap().values() {
            assert!(!String::from_utf8_lossy(request).contains("Hello"));
            assert!(!String::from_utf8_lossy(response).contains("Hello"));
        }
    }
}
#[tokio::test]
async fn integrated_ohttp_authenticates_config_and_verifies_inner_receipts() {
    for direct in [false, true] {
        for case in ["valid", "alternate_spelling", "missing", "wrong_signer"] {
            let (_server, f, mut options) = setup(Fixture {
                direct,
                ohttp: if case == "missing" {
                    None
                } else {
                    Some(ohttp_config())
                },
                wrong_ohttp_signer: case == "wrong_signer",
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
                                .await,
                        )
                    } else {
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
                                .await,
                        )
                    } else {
                        None
                    };
                    (result, receipt)
                };
                if case == "valid" || case == "alternate_spelling" {
                    assert!(String::from_utf8(result.unwrap())
                        .unwrap()
                        .contains("Hello"));
                    let receipt = receipt.unwrap().unwrap();
                    if direct {
                        match receipt.attestation {
                            VerifiedCompletionAttestation::Direct(reports) => {
                                assert_eq!(reports.len(), 2)
                            }
                            _ => panic!("expected direct reports"),
                        }
                    }
                } else {
                    assert!(result.is_err());
                    assert_eq!(f.chat.load(Ordering::SeqCst), 0);
                }
            }
        }
    }
}

#[tokio::test]
async fn receipt_cache_bounds_combined_request_and_response_bytes() {
    let (_server, f, mut options) = setup(Fixture::default()).await;
    // Measure an actual receipt so the budget fits exactly one completion.
    let probe = InferenceClient::with_options(options.clone()).unwrap();
    probe.chat_completions(body()).await.unwrap();
    let size = {
        let receipts = f.receipts.lock().unwrap();
        let (request, response, _) = &receipts["chat-0"];
        request.len() + response.len()
    };
    options.max_receipt_cache_bytes = size;
    let client = InferenceClient::with_options(options.clone()).unwrap();
    client.chat_completions(body()).await.unwrap();
    client.verify_response("chat-1").await.unwrap();
    client.chat_completions(body()).await.unwrap();
    assert_eq!(
        client.verify_response("chat-1").await.unwrap_err().code(),
        "api.completion_not_found"
    );
    client.verify_response("chat-2").await.unwrap();
    // An oversized request must count, even when its response is small.
    let mut large = body();
    large["extra"] = json!("x".repeat(size));
    assert!(client.chat_completions(large).await.is_err());
    client.verify_response("chat-2").await.unwrap();
    assert_eq!(
        client.verify_response("chat-3").await.unwrap_err().code(),
        "api.completion_not_found"
    );
    options.max_receipt_cache_bytes = size - 1;
    let client = InferenceClient::with_options(options.clone()).unwrap();
    assert!(client.chat_completions(body()).await.is_err());
    options.max_receipt_cache_bytes = 0;
    assert!(InferenceClient::with_options(options.clone()).is_err());
    assert!(DirectInferenceClient::with_options(options.into()).is_err());
}

#[tokio::test]
async fn canceled_receipt_verification_releases_byte_capacity() {
    let (_server, f, mut options) = setup(Fixture::default()).await;
    let probe = InferenceClient::with_options(options.clone()).unwrap();
    probe.chat_completions(body()).await.unwrap();
    {
        let receipts = f.receipts.lock().unwrap();
        let (request, response, _) = &receipts["chat-0"];
        options.max_receipt_cache_bytes = request.len() + response.len();
    }
    let client = InferenceClient::with_options(options).unwrap();
    client.chat_completions(body()).await.unwrap();
    {
        let verification = client.verify_response("chat-1");
        tokio::pin!(verification);
        tokio::select! {
            result = &mut verification => panic!("verification finished before cancellation: {result:?}"),
            _ = f.signature_started.notified() => {},
        }
    }
    client.chat_completions(body()).await.unwrap();
    assert_eq!(client.verify_response("chat-2").await.unwrap().id, "chat-2");
}

#[tokio::test]
async fn evicted_verification_keeps_capacity() {
    for eviction in ["count", "bytes", "expiry"] {
        let (_server, f, mut options) = setup(Fixture::default()).await;
        let probe = InferenceClient::with_options(options.clone()).unwrap();
        probe.chat_completions(body()).await.unwrap();
        if eviction == "bytes" {
            let receipts = f.receipts.lock().unwrap();
            let (request, response, _) = &receipts["chat-0"];
            options.max_receipt_cache_bytes = request.len() + response.len();
        }
        if eviction == "count" {
            options.max_cache_entries = 1;
        }
        if eviction == "expiry" {
            options.response_cache_ttl = Duration::from_millis(20);
        }
        let client = InferenceClient::with_options(options).unwrap();
        client.chat_completions(body()).await.unwrap();
        let verification = client.verify_response("chat-1");
        tokio::pin!(verification);
        tokio::select! {
            result = &mut verification => panic!("verification finished before eviction: {result:?}"),
            _ = f.signature_started.notified() => {},
        }
        if eviction == "expiry" {
            tokio::time::sleep(Duration::from_millis(40)).await;
        } else {
            client.chat_completions(body()).await.unwrap();
            assert_eq!(
                client.verify_response("chat-2").await.unwrap_err().code(),
                if eviction == "count" {
                    "api.invalid_input"
                } else {
                    "api.completion_not_found"
                }
            );
        }
        assert_eq!(
            client.verify_response("chat-1").await.unwrap_err().code(),
            "api.completion_not_found"
        );
        assert_eq!(verification.await.unwrap().id, "chat-1");
        if eviction != "count" {
            client.chat_completions(body()).await.unwrap();
        }
        client
            .verify_response(if eviction == "bytes" {
                "chat-3"
            } else {
                "chat-2"
            })
            .await
            .unwrap();
    }
}

fn systemone_request() -> Value {
    json!({
        "model": "vendor/model",
        "state": {"text": "hello"},
        "questions": {
            "q": {
                "type": "noul",
                "instructions": "Is this a greeting?"
            }
        }
    })
}

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
async fn systemone_compressed_responses() {
    for encoding in ["gzip", "br"] {
        for mode in ["receipt", "tamper", "limit"] {
            let (_server, f, mut options) = setup(Fixture {
                response_encoding: Some(encoding),
                systemone_tamper: mode == "tamper",
                systemone_body: (mode == "limit").then(|| format!("{{}}{}", " ".repeat(4096))),
                ..Default::default()
            })
            .await;
            if mode == "limit" {
                options.max_response_bytes = 2048;
            }
            let client = InferenceClient::with_options(options).unwrap();
            let result = client.systemone_create(&systemone_request()).await;
            if mode == "limit" {
                assert_eq!(result.unwrap_err().code(), "api.invalid_input");
            } else {
                let receipt = client.verify_response(&result.unwrap().decision_id).await;
                if mode == "tamper" {
                    assert_eq!(receipt.unwrap_err().code(), "signature.payload_mismatch");
                } else {
                    receipt.unwrap();
                }
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

#[tokio::test]
async fn systemone_retained_receipts_follow_size_and_count_limits() {
    let (_server, _, mut options) = setup(Fixture::default()).await;
    options.max_cache_entries = 1;
    let client = InferenceClient::with_options(options).unwrap();

    let first = client.systemone_create(&systemone_request()).await.unwrap();
    let second = client.systemone_create(&systemone_request()).await.unwrap();
    assert_eq!(
        client
            .verify_response(&first.decision_id)
            .await
            .unwrap_err()
            .code(),
        "api.completion_not_found"
    );

    client.verify_response(&second.decision_id).await.unwrap();

    let (_server, f, mut options) = setup(Fixture::default()).await;
    options.max_receipt_cache_bytes = serde_json::to_vec(&systemone_request()).unwrap().len();
    let client = InferenceClient::with_options(options.clone()).unwrap();

    assert!(client.systemone_create(&systemone_request()).await.is_err());
    assert_eq!(f.systemone.load(Ordering::SeqCst), 0);

    options.response_cache_ttl = Duration::ZERO;
    let client = InferenceClient::with_options(options).unwrap();
    let result = client.systemone_create(&systemone_request()).await.unwrap();
    assert_eq!(f.systemone.load(Ordering::SeqCst), 1);
    assert_eq!(
        client
            .verify_response(&result.decision_id)
            .await
            .unwrap_err()
            .code(),
        "api.completion_not_found"
    );
}

fn response_request_body(streaming: bool) -> Value {
    json!({
        "model": "vendor/model",
        "store": false,
        "stream": streaming,
        "input": [
            {
                "type": "function_call",
                "call_id": "prior",
                "name": "weather",
                "arguments": "{}"
            },
            {
                "type": "function_call_output",
                "call_id": "prior",
                "output": "{\"temperature\":20}"
            }
        ]
    })
}

#[tokio::test]
async fn responses_json_and_sse_retain_exact_gateway_receipts() {
    for streaming in [false, true] {
        for oblivious in [false, true] {
            let fixture = Fixture {
                ohttp: oblivious.then(|| {
                    ohttp::KeyConfig::new(
                        1,
                        ohttp::hpke::Kem::X25519Sha256,
                        vec![ohttp::SymmetricSuite::new(
                            ohttp::hpke::Kdf::HkdfSha256,
                            ohttp::hpke::Aead::Aes128Gcm,
                        )],
                    )
                    .unwrap()
                }),
                ..Default::default()
            };
            let (_server, f, mut options) = setup(fixture).await;
            options.ohttp = oblivious;
            let client = InferenceClient::with_options(options).unwrap();
            let body = response_request_body(streaming);

            if streaming {
                let response = client
                    .send(client.response_request(body).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.bytes().await.unwrap(),
                    include_bytes!("../test-fixtures/responses/response.sse")
                );
            } else {
                let response = client.create_response(body).await.unwrap();
                assert_eq!(response["id"], "resp_fixture");
                assert_eq!(response["output"][2]["arguments"], "{\"city\":\"北京\"}");
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
async fn responses_enforce_body_and_receipt_limits() {
    for streaming in [false, true] {
        for receipt_limit in [false, true] {
            let (_server, f, mut options) = setup(Fixture::default()).await;
            if receipt_limit {
                options.max_receipt_cache_bytes = 512;
            } else {
                options.max_response_bytes = 512;
            }
            let client = InferenceClient::with_options(options).unwrap();
            let response = client
                .send(
                    client
                        .response_request(response_request_body(streaming))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.bytes().await.unwrap_err().code(),
                "api.invalid_input"
            );
            assert_eq!(
                client
                    .verify_response("resp_fixture")
                    .await
                    .unwrap_err()
                    .code(),
                "api.completion_not_found"
            );
            assert_eq!(f.chat.load(Ordering::SeqCst), 1);
        }
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
    let direct = DirectInferenceClient::with_options(options.clone().into()).unwrap();
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
