#[path = "encryption.rs"]
mod encryption;
use super::support::{model_quote, sha256_hex, APP_COMPOSE};
use async_trait::async_trait;
use ed25519_dalek::Signer;
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use nearai_inference_sdk::*;
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

pub(super) struct Quote;
#[async_trait]
impl TdxQuoteVerifier for Quote {
    async fn verify(&self, quote: &str) -> Result<TdxQuoteVerificationResult, VerificationError> {
        let mut result = model_quote(TcbStatus::UpToDate);
        let quote = if let Some((label, quote)) = quote.split_once(':') {
            result.advisory_ids.push(label.to_owned());
            quote
        } else {
            quote
        };
        result.report_data = hex::decode(quote).unwrap();
        Ok(result)
    }
}
type ReceiptBytes = (Vec<u8>, Vec<u8>, String);
#[derive(Default)]
pub(super) struct Fixture {
    pub(super) response_encoding: Option<&'static str>,
    pub(super) gateway: AtomicUsize,
    pub(super) model: AtomicUsize,
    pub(super) chat: AtomicUsize,
    pub(super) systemone: AtomicUsize,
    pub(super) systemone_body: Option<String>,
    pub(super) systemone_id: Option<String>,
    pub(super) systemone_status: Option<u16>,
    pub(super) missing_model_key: bool,
    pub(super) first_model_key_missing: bool,
    pub(super) extra_model: bool,
    pub(super) shared_model: bool,
    pub(super) gateway_chat_receipt: bool,
    pub(super) systemone_tamper: bool,

    pub(super) signatures: AtomicUsize,
    pub(super) receipts: Mutex<std::collections::HashMap<String, ReceiptBytes>>,
    pub(super) metadata: Mutex<Option<Value>>,
    pub(super) empty: bool,
    pub(super) bad_key: bool,
    pub(super) bad_model: bool,
    pub(super) retry_signature: bool,
    pub(super) wrong_signer: bool,
    pub(super) wrong_algo: bool,
    pub(super) direct: bool,
    pub(super) header_auth: bool,
    pub(super) ecdsa: bool,
    pub(super) ohttp: Option<ohttp::KeyConfig>,
    pub(super) wrong_ohttp_signer: bool,
    pub(super) bad_ohttp_signature: bool,
    pub(super) bad_ohttp_config: bool,
    pub(super) tampered_ohttp_response: bool,
    pub(super) alternate_direct_signer: bool,
    pub(super) response_body: Option<Vec<u8>>,
    pub(super) response_provider_receipt: bool,
    pub(super) response_tamper: bool,
    pub(super) response_status: Option<u16>,
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
            let bytes = if self.bad_ohttp_config {
                vec![1, 2, 3]
            } else {
                config.encode().unwrap()
            };
            let signer = key(if self.wrong_ohttp_signer {
                8
            } else if self.direct {
                7
            } else {
                9
            });
            value["ohttp_attestation"] = json!({"signing_algo":"ed25519","signing_key":hex::encode(signer.verifying_key().as_bytes()),"key_config":hex::encode(&bytes),"signature":hex::encode(signer.sign(&bytes).to_bytes())});
            if self.bad_ohttp_signature {
                value["ohttp_attestation"]["signature"] = json!("00".repeat(64));
            }
        }
        value
    }
}
impl Respond for Fixture {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        if r.url.path() == "/v1/attestation/report"
            && (self.direct || !r.url.query_pairs().any(|(name, _)| name == "model"))
        {
            for name in ["authorization", "api-key", "x-api-key"] {
                assert!(r.headers.get(name).is_none(), "attestation sent {name}");
            }
        } else if self.header_auth {
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
                    let generation = self.model.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(r.headers.get("x-no-aliasing").unwrap(), "true");
                    let mut value = self.report(nonce, 7);
                    if self.bad_key {
                        value["signing_public_key"] =
                            json!(hex::encode(key(8).verifying_key().as_bytes()));
                    }
                    let mut reports = vec![value];
                    if self.extra_model {
                        reports.insert(usize::from(self.shared_model), self.report(nonce, 8));
                    }
                    if self.shared_model {
                        let mut other = self.report(nonce, 7);
                        other["intel_quote"] = json!(format!(
                            "shared-{generation}:{}",
                            other["intel_quote"].as_str().unwrap()
                        ));
                        if self.bad_model {
                            other["report_data"] = json!("ff".repeat(64));
                        }
                        reports.push(other);
                    } else if self.bad_model {
                        let mut bad = self.report(nonce, 8);
                        bad["report_data"] = json!("ff".repeat(64));
                        reports.push(bad);
                    }
                    if self.first_model_key_missing {
                        let mut no_key = self.report(nonce, 8);
                        no_key.as_object_mut().unwrap().remove("signing_public_key");
                        reports.insert(0, no_key);
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
                            "../../test-fixtures/systemone-responses.json"
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
                        include_bytes!("../../test-fixtures/responses/response.sse").to_vec()
                    } else {
                        include_bytes!("../../test-fixtures/responses/response.json").to_vec()
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
            "/v1/messages" => {
                self.chat.fetch_add(1, Ordering::SeqCst);
                assert!(self.gateway.load(Ordering::SeqCst) > 0);
                assert_eq!(r.headers.get("x-no-aliasing").unwrap(), "true");
                assert!(r.headers.get("x-client-pub-key").is_none());
                let request: Value = serde_json::from_slice(&r.body).unwrap();
                assert_eq!(request["messages"][1]["role"], "user");
                assert!(r.headers.get("x-model-pub-key").is_none());
                assert!(r.headers.get("x-api-key").is_none());
                assert!(r.headers.get("anthropic-version").is_some());
                let streaming = request["stream"] == true;
                let raw = self.response_body.clone().unwrap_or_else(|| {
                    if streaming {
                        include_bytes!("../../test-fixtures/messages/message.sse").to_vec()
                    } else {
                        include_bytes!("../../test-fixtures/messages/message.json").to_vec()
                    }
                });
                self.receipts.lock().unwrap().insert(
                    "msg_fixture".into(),
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
                        .replace("Hello", "Altered")
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
                let kind = if self.gateway_chat_receipt || self.metadata.lock().unwrap().is_some() {
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
                let id = if inner.url.path() == "/v1/messages" {
                    "msg_fixture".into()
                } else if inner.url.path() == "/v1/responses" {
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
                if self.tampered_ohttp_response {
                    *encrypted.last_mut().unwrap() ^= 1;
                }
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
pub(super) async fn setup(fixture: Fixture) -> (MockServer, Arc<Fixture>, InferenceClientOptions) {
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
pub(super) fn body() -> Value {
    json!({"model":"vendor/model","messages":[{"role":"user","content":"Hello"}]})
}

pub(super) fn ohttp_config() -> ohttp::KeyConfig {
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

pub(super) fn systemone_request() -> Value {
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

pub(super) fn response_request_body(streaming: bool) -> Value {
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
