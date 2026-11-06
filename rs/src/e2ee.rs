//! Wire-compatible Ed25519-v2 and legacy ECDSA field encryption.
use crate::{
    errors::protocol, util::decode_hex, ApiError, InferenceError, SigningAlgo, VerificationError,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use chacha20poly1305::XChaCha20Poly1305;
use k256::elliptic_curve::{sec1::ToSec1Point, Generate};
use rand::{rngs::OsRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone, Debug)]
pub struct E2eeModelKey {
    pub signing_algo: SigningAlgo,
    pub public_key: String,
}
// No Debug/Serialize implementation: response secrets must never enter logs.
pub(crate) enum ResponseKey {
    Ed25519(x25519_dalek::StaticSecret),
    Ecdsa(k256::SecretKey),
}
fn invalid() -> VerificationError {
    protocol("e2ee.model_public_key_invalid", "invalid model public key")
}
fn derive(shared: &[u8], algo: SigningAlgo) -> Result<[u8; 32], VerificationError> {
    if shared.iter().all(|b| *b == 0) {
        return Err(invalid());
    }
    let mut key = [0; 32];
    let label: &[u8] = match algo {
        SigningAlgo::Ed25519 => b"ed25519_encryption",
        SigningAlgo::Ecdsa => b"ecdsa_encryption",
    };
    hkdf::Hkdf::<Sha256>::new(None, shared)
        .expand(label, &mut key)
        .map_err(|_| invalid())?;
    Ok(key)
}
impl ResponseKey {
    fn generate(algo: SigningAlgo) -> (Self, String) {
        match algo {
            SigningAlgo::Ed25519 => {
                let mut seed = [0; 32];
                OsRng.fill_bytes(&mut seed);
                let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
                let hash = Sha512::digest(seed);
                let mut scalar = [0; 32];
                scalar.copy_from_slice(&hash[..32]);
                (
                    Self::Ed25519(x25519_dalek::StaticSecret::from(scalar)),
                    hex::encode(signing.verifying_key().as_bytes()),
                )
            }
            SigningAlgo::Ecdsa => {
                let secret = k256::SecretKey::generate();
                let public = hex::encode(&secret.public_key().to_sec1_point(false).as_bytes()[1..]);
                (Self::Ecdsa(secret), public)
            }
        }
    }
    fn decrypt(&self, value: &str) -> Result<String, VerificationError> {
        if value.is_empty() {
            return Ok(String::new());
        }
        let failed = || protocol("e2ee.decryption_failed", "field authentication failed");
        let data = decode_hex(value).map_err(|_| failed())?;
        let plaintext = match self {
            Self::Ed25519(secret) => {
                if data.len() < 72 {
                    return Err(failed());
                }
                let public: [u8; 32] = data[..32].try_into().map_err(|_| failed())?;
                let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(public));
                let key = derive(shared.as_bytes(), SigningAlgo::Ed25519).map_err(|_| failed())?;
                XChaCha20Poly1305::new((&key).into())
                    .decrypt(data[32..56].into(), &data[56..])
                    .map_err(|_| failed())?
            }
            Self::Ecdsa(secret) => {
                if data.len() < 93 || data[0] != 4 {
                    return Err(failed());
                }
                let public = k256::PublicKey::from_sec1_bytes(&data[..65]).map_err(|_| failed())?;
                let shared =
                    k256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
                let key =
                    derive(shared.raw_secret_bytes(), SigningAlgo::Ecdsa).map_err(|_| failed())?;
                Aes256Gcm::new((&key).into())
                    .decrypt(data[65..77].into(), &data[77..])
                    .map_err(|_| failed())?
            }
        };
        String::from_utf8(plaintext).map_err(|_| failed())
    }
}
fn encrypt(value: &str, model: &E2eeModelKey) -> Result<String, VerificationError> {
    let public = decode_hex(&model.public_key).map_err(|_| invalid())?;
    let (mut data, key, size) = match model.signing_algo {
        SigningAlgo::Ed25519 => {
            let encoded: [u8; 32] = public.try_into().map_err(|_| invalid())?;
            let point = curve25519_dalek::edwards::CompressedEdwardsY(encoded)
                .decompress()
                .ok_or_else(invalid)?;
            if point.is_small_order() || !point.is_torsion_free() {
                return Err(invalid());
            }
            let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(
                point.to_montgomery().to_bytes(),
            ));
            (
                x25519_dalek::PublicKey::from(&secret).as_bytes().to_vec(),
                derive(shared.as_bytes(), model.signing_algo)?,
                24,
            )
        }
        SigningAlgo::Ecdsa => {
            let mut encoded = public;
            if encoded.len() == 64 {
                encoded.insert(0, 4);
            }
            if encoded.len() != 65 || encoded[0] != 4 {
                return Err(invalid());
            }
            let recipient = k256::PublicKey::from_sec1_bytes(&encoded).map_err(|_| invalid())?;
            let secret = k256::SecretKey::generate();
            let shared =
                k256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), recipient.as_affine());
            (
                secret.public_key().to_sec1_point(false).as_bytes().to_vec(),
                derive(shared.raw_secret_bytes(), model.signing_algo)?,
                12,
            )
        }
    };
    let mut nonce = vec![0; size];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = if size == 24 {
        XChaCha20Poly1305::new((&key).into()).encrypt(nonce.as_slice().into(), value.as_bytes())
    } else {
        Aes256Gcm::new((&key).into()).encrypt(nonce.as_slice().into(), value.as_bytes())
    }
    .map_err(|_| invalid())?;
    data.extend(nonce);
    data.extend(encrypted);
    Ok(hex::encode(data))
}
fn fields(
    target: &mut Value,
    names: &[&str],
    transform: &impl Fn(&str) -> Result<String, VerificationError>,
) -> Result<(), VerificationError> {
    for name in names {
        if let Some(value) = target.get_mut(*name) {
            if let Some(text) = value.as_str() {
                *value = Value::String(transform(text)?);
            }
        }
    }
    Ok(())
}
fn objects(value: Option<&mut Value>) -> impl Iterator<Item = &mut Value> {
    value
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
        .filter(|v| v.is_object())
}
fn encrypt_request(body: &mut Value, model: &E2eeModelKey) -> Result<(), VerificationError> {
    let transform = |s: &str| encrypt(s, model);
    for message in objects(body.get_mut("messages")) {
        if let Some(content) = message.get_mut("content") {
            if content.is_array() {
                *content = Value::String(transform(&content.to_string())?);
            } else if let Some(text) = content.as_str() {
                *content = Value::String(transform(text)?);
            }
        }
        fields(
            message,
            &["reasoning_content", "reasoning", "name", "refusal"],
            &transform,
        )?;
        if let Some(audio) = message.get_mut("audio") {
            fields(audio, &["data"], &transform)?;
        }
        for call in objects(message.get_mut("tool_calls")) {
            if let Some(f) = call.get_mut("function") {
                fields(f, &["name", "arguments"], &transform)?;
            }
        }
        if let Some(f) = message.get_mut("function_call") {
            fields(f, &["name", "arguments"], &transform)?;
        }
    }
    for tool in objects(body.get_mut("tools")) {
        if let Some(f) = tool.get_mut("function") {
            fields(f, &["name", "description"], &transform)?;
            if let Some(parameters) = f.get_mut("parameters") {
                *parameters = Value::String(transform(&parameters.to_string())?);
            }
        }
    }
    if let Some(f) = body
        .get_mut("tool_choice")
        .and_then(|v| v.get_mut("function"))
    {
        fields(f, &["name"], &transform)?;
    }
    if let Some(f) = body.get_mut("function_call") {
        fields(f, &["name"], &transform)?;
    }
    Ok(())
}
pub(crate) fn decrypt_response(
    body: &mut Value,
    key: &ResponseKey,
    streaming: bool,
) -> Result<(), VerificationError> {
    let transform = |s: &str| key.decrypt(s);
    for choice in objects(body.get_mut("choices")) {
        if let Some(message) = choice.get_mut(if streaming { "delta" } else { "message" }) {
            fields(
                message,
                &["content", "reasoning_content", "reasoning", "refusal"],
                &transform,
            )?;
            for part in objects(message.get_mut("content")) {
                fields(part, &["text"], &transform)?;
            }
            if let Some(audio) = message.get_mut("audio") {
                fields(audio, &["data"], &transform)?;
            }
            for call in objects(message.get_mut("tool_calls")) {
                if let Some(f) = call.get_mut("function") {
                    fields(f, &["name", "arguments"], &transform)?;
                }
            }
            if let Some(f) = message.get_mut("function_call") {
                fields(f, &["name", "arguments"], &transform)?;
            }
            if streaming {
                if let Some(f) = message.get_mut("nearai_tool_result") {
                    fields(f, &["output"], &transform)?;
                }
            }
        }
        if let Some(logprobs) = choice.get_mut("logprobs") {
            for name in ["content", "refusal"] {
                decrypt_logprobs(logprobs.get_mut(name), key)?;
            }
        }
    }
    Ok(())
}
fn decrypt_logprobs(value: Option<&mut Value>, key: &ResponseKey) -> Result<(), VerificationError> {
    for entry in objects(value) {
        fields(entry, &["token"], &|s| key.decrypt(s))?;
        if let Some(raw) = entry.get_mut("bytes") {
            if let Some(text) = raw.as_str() {
                *raw = serde_json::from_str(&key.decrypt(text)?)
                    .map_err(|_| protocol("e2ee.decryption_failed", "invalid logprob bytes"))?;
            }
        }
        decrypt_logprobs(entry.get_mut("top_logprobs"), key)?;
    }
    Ok(())
}
/// Encrypted request and a private response key. Caller must authenticate the model key first.
pub struct PreparedE2eeChatRequest {
    pub request: reqwest::Request,
    pub(crate) key: ResponseKey,
}
impl PreparedE2eeChatRequest {
    pub fn decrypt_json(&self, bytes: &[u8]) -> Result<Value, InferenceError> {
        let mut value: Value = serde_json::from_slice(bytes).map_err(|_| invalid_response())?;
        if !value.is_object() {
            return Err(invalid_response().into());
        }
        decrypt_response(&mut value, &self.key, false)?;
        Ok(value)
    }
}
pub(crate) fn invalid_response() -> ApiError {
    ApiError::InvalidResponse {
        path: "Chat Completions response".into(),
        expected: "a JSON object with a nonempty id".into(),
        actual: "invalid".into(),
    }
}
pub(crate) fn decode_request(request: &reqwest::Request) -> Result<Value, ApiError> {
    let value = request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .and_then(|b| serde_json::from_slice::<Value>(b).ok());
    match value {
        Some(value)
            if request.method() == reqwest::Method::POST
                && value
                    .get("model")
                    .and_then(Value::as_str)
                    .is_some_and(|m| !m.is_empty() && m != "." && m != "..") =>
        {
            Ok(value)
        }
        _ => Err(ApiError::InvalidInput {
            field: "request".into(),
            reason: "expected a buffered JSON POST with a nonempty model".into(),
            expected: None,
            actual: None,
        }),
    }
}
pub(crate) fn remove_e2ee_headers(headers: &mut reqwest::header::HeaderMap) {
    for name in [
        "x-signing-algo",
        "x-client-pub-key",
        "x-model-pub-key",
        "x-encryption-version",
        "x-encrypt-all-fields",
    ] {
        headers.remove(name);
    }
}
pub fn prepare_e2ee_chat_request(
    mut request: reqwest::Request,
    model: &E2eeModelKey,
) -> Result<PreparedE2eeChatRequest, InferenceError> {
    let mut value = decode_request(&request)?;
    encrypt_request(&mut value, model)?;
    let (key, public) = ResponseKey::generate(model.signing_algo);
    let headers = request.headers_mut();
    for name in [
        "content-length",
        "transfer-encoding",
        "trailer",
        "content-md5",
        "digest",
        "content-digest",
        "repr-digest",
        "content-encoding",
        "etag",
        "last-modified",
    ] {
        headers.remove(name);
    }
    remove_e2ee_headers(headers);
    for (name, value) in [
        ("content-type", "application/json".into()),
        ("x-signing-algo", model.signing_algo.to_string()),
        ("x-client-pub-key", public),
        ("x-model-pub-key", model.public_key.clone()),
        ("x-no-aliasing", "true".into()),
        ("x-encrypt-all-fields", "true".into()),
    ] {
        headers.insert(
            reqwest::header::HeaderName::from_static(name),
            value.parse().map_err(|_| invalid())?,
        );
    }
    if model.signing_algo == SigningAlgo::Ed25519 {
        headers.insert(
            "x-encryption-version",
            reqwest::header::HeaderValue::from_static("2"),
        );
    }
    *request.body_mut() = Some(value.to_string().into());
    Ok(PreparedE2eeChatRequest { request, key })
}
impl PreparedE2eeChatRequest {
    /// Decrypt SSE under consumer backpressure. This helper performs no attestation
    /// or receipt verification; retain the original wire bytes separately.
    pub fn decrypt_sse(self, mut source: crate::ByteStream) -> crate::ByteStream {
        use futures_util::StreamExt;
        Box::pin(async_stream::try_stream! {
            let mut decoder = crate::sse::SseDecoder::default();
            let mut id = None;
            while let Some(chunk) = source.next().await {
                let chunk = chunk?;
                for record in decoder.push(&chunk, false) {
                    yield bytes::Bytes::from(crate::sse::transform(&record, Some(&self.key), &mut id, false, false)?);
                }
            }
            for record in decoder.push(&[], true) {
                yield bytes::Bytes::from(crate::sse::transform(&record, Some(&self.key), &mut id, false, false)?);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixed_key(algo: SigningAlgo) -> (ResponseKey, E2eeModelKey) {
        let seed = [7; 32];
        match algo {
            SigningAlgo::Ed25519 => {
                let hash = Sha512::digest(seed);
                let scalar: [u8; 32] = hash[..32].try_into().unwrap();
                (
                    ResponseKey::Ed25519(x25519_dalek::StaticSecret::from(scalar)),
                    E2eeModelKey {
                        signing_algo: algo,
                        public_key: hex::encode(
                            ed25519_dalek::SigningKey::from_bytes(&seed)
                                .verifying_key()
                                .as_bytes(),
                        ),
                    },
                )
            }
            SigningAlgo::Ecdsa => {
                let secret = k256::SecretKey::from_slice(&seed).unwrap();
                let public_key =
                    hex::encode(&secret.public_key().to_sec1_point(false).as_bytes()[1..]);
                (
                    ResponseKey::Ecdsa(secret),
                    E2eeModelKey {
                        signing_algo: algo,
                        public_key,
                    },
                )
            }
        }
    }
    #[test]
    fn decrypts_python_wire_vectors_and_rejects_tampering() {
        let fixtures: Value =
            serde_json::from_str(include_str!("../tests/fixtures/e2ee-python.json")).unwrap();
        for case in fixtures["cases"].as_array().unwrap() {
            let algo = if case["algorithm"] == "ed25519" {
                SigningAlgo::Ed25519
            } else {
                SigningAlgo::Ecdsa
            };
            let (key, model) = fixed_key(algo);
            assert_eq!(model.public_key, case["public_key"]);
            let ciphertext = case["ciphertext"].as_str().unwrap();
            assert_eq!(key.decrypt(ciphertext).unwrap(), case["plaintext"]);
            let mut bytes = hex::decode(ciphertext).unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            assert_eq!(
                key.decrypt(&hex::encode(bytes)).unwrap_err().code(),
                "e2ee.decryption_failed"
            );
            assert_eq!(
                key.decrypt(&encrypt("Rust → Python-compatible wire", &model).unwrap())
                    .unwrap(),
                "Rust → Python-compatible wire"
            );
        }
    }
    #[test]
    fn encrypts_supported_fields_without_changing_routing_or_unknown_fields() {
        for algo in [SigningAlgo::Ed25519, SigningAlgo::Ecdsa] {
            let (key, model_key) = fixed_key(algo);
            let original = json!({
                "model": "vendor/model",
                "messages": [{
                    "role": "user", "name": "Alice", "content": [{"type": "text", "text": "secret"}],
                    "reasoning_content": "analysis", "reasoning": "thought", "refusal": "no",
                    "audio": {"data": "audio", "format": "wav"},
                    "tool_calls": [{"id": "call-1", "type": "function", "function": {"name": "run", "arguments": "{}"}}],
                    "function_call": {"name": "legacy", "arguments": "[]"}, "unknown": "preserved"
                }, {"role": "assistant", "content": "answer"}],
                "tools": [{"type": "function", "function": {"name": "run", "description": "desc", "parameters": {"type": "object"}}}],
                "tool_choice": {"type": "function", "function": {"name": "run"}},
                "function_call": {"name": "legacy"}, "temperature": 0.5, "metadata": {"tag": "public"}
            });
            let mut request = reqwest::Request::new(
                reqwest::Method::POST,
                "https://example.com/v1/chat/completions".parse().unwrap(),
            );
            *request.body_mut() = Some(original.to_string().into());
            let prepared = prepare_e2ee_chat_request(request, &model_key).unwrap();
            let mut encrypted: Value =
                serde_json::from_slice(prepared.request.body().unwrap().as_bytes().unwrap())
                    .unwrap();
            // Every protected field must independently decrypt to its original
            // value. Comparing the complete object also protects routing and
            // extension fields from accidental transformation.
            for path in [
                "/messages/0/name",
                "/messages/0/reasoning_content",
                "/messages/0/reasoning",
                "/messages/0/refusal",
                "/messages/0/audio/data",
                "/messages/0/tool_calls/0/function/name",
                "/messages/0/tool_calls/0/function/arguments",
                "/messages/0/function_call/name",
                "/messages/0/function_call/arguments",
                "/messages/1/content",
                "/tools/0/function/name",
                "/tools/0/function/description",
                "/tool_choice/function/name",
                "/function_call/name",
            ] {
                let value = encrypted.pointer_mut(path).unwrap();
                assert_ne!(value, original.pointer(path).unwrap(), "{algo}: {path}");
                *value = Value::String(key.decrypt(value.as_str().unwrap()).unwrap());
            }
            for path in ["/messages/0/content", "/tools/0/function/parameters"] {
                let value = encrypted.pointer_mut(path).unwrap();
                *value =
                    serde_json::from_str(&key.decrypt(value.as_str().unwrap()).unwrap()).unwrap();
            }
            assert_eq!(encrypted, original, "{algo}");
        }
    }
    #[test]
    fn decrypts_tools_reasoning_audio_and_logprobs() {
        for algo in [SigningAlgo::Ed25519, SigningAlgo::Ecdsa] {
            for streaming in [false, true] {
                let (key, model_key) = fixed_key(algo);
                let message_field = if streaming { "delta" } else { "message" };
                let mut message = json!({
                    "role": "assistant", "content": "answer", "reasoning_content": "analysis",
                    "reasoning": "thought", "refusal": "no", "audio": {"data": "audio", "id": "audio-1"},
                    "tool_calls": [{"id": "call-1", "type": "function", "function": {"name": "run", "arguments": "{}"}}],
                    "function_call": {"name": "legacy", "arguments": "[]"}, "unknown": "preserved"
                });
                if streaming {
                    message["nearai_tool_result"] = json!({"output": "output", "id": "result-1"});
                }
                let original = json!({"id": "chat-1", "choices": [{
                    "index": 0, message_field: message, "finish_reason": "stop",
                    "logprobs": {
                        "content": [{"token": "word", "bytes": [1, 2, 3], "logprob": -0.1,
                            "top_logprobs": [{"token": "other", "bytes": [4], "logprob": -0.2}]}],
                        "refusal": [{"token": "no", "bytes": [5], "logprob": -0.3}]
                    }
                }, {"index": 1, message_field: {"content": [{"type": "text", "text": "part"}]}}]});
                let mut encrypted = original.clone();
                for suffix in [
                    "content",
                    "reasoning_content",
                    "reasoning",
                    "refusal",
                    "audio/data",
                    "tool_calls/0/function/name",
                    "tool_calls/0/function/arguments",
                    "function_call/name",
                    "function_call/arguments",
                ] {
                    let path = format!("/choices/0/{message_field}/{suffix}");
                    let value = encrypted.pointer_mut(&path).unwrap();
                    *value = Value::String(encrypt(value.as_str().unwrap(), &model_key).unwrap());
                }
                let path = format!("/choices/1/{message_field}/content/0/text");
                encrypted
                    .pointer_mut(&path)
                    .unwrap()
                    .clone_from(&json!(encrypt("part", &model_key).unwrap()));
                if streaming {
                    encrypted["choices"][0][message_field]["nearai_tool_result"]["output"] =
                        json!(encrypt("output", &model_key).unwrap());
                }
                for path in [
                    "/choices/0/logprobs/content/0",
                    "/choices/0/logprobs/content/0/top_logprobs/0",
                    "/choices/0/logprobs/refusal/0",
                ] {
                    let entry = encrypted.pointer_mut(path).unwrap();
                    entry["token"] =
                        json!(encrypt(entry["token"].as_str().unwrap(), &model_key).unwrap());
                    entry["bytes"] =
                        json!(encrypt(&entry["bytes"].to_string(), &model_key).unwrap());
                }
                decrypt_response(&mut encrypted, &key, streaming).unwrap();
                assert_eq!(encrypted, original, "{algo}, streaming={streaming}");
            }
        }
    }
    #[test]
    fn each_prepared_request_has_fresh_key_and_replaces_encryption_headers() {
        for algo in [SigningAlgo::Ed25519, SigningAlgo::Ecdsa] {
            let (_, model) = fixed_key(algo);
            let request = || {
                let mut r = reqwest::Request::new(
                    reqwest::Method::POST,
                    "https://example.com/v1/chat/completions".parse().unwrap(),
                );
                *r.body_mut() = Some(
                    json!({"model":"vendor/model","messages":[{"content":"private"}]})
                        .to_string()
                        .into(),
                );
                for (n, v) in [
                    ("content-length", "1"),
                    ("x-client-pub-key", "attacker"),
                    ("x-encryption-version", "99"),
                    ("digest", "stale"),
                ] {
                    r.headers_mut().insert(n, v.parse().unwrap());
                }
                r
            };
            let a = prepare_e2ee_chat_request(request(), &model).unwrap();
            let b = prepare_e2ee_chat_request(request(), &model).unwrap();
            assert_ne!(
                a.request.headers()["x-client-pub-key"],
                b.request.headers()["x-client-pub-key"]
            );
            assert!(!a.request.headers().contains_key("digest"));
            assert!(!a.request.headers().contains_key("content-length"));
            assert_eq!(
                a.request.headers().contains_key("x-encryption-version"),
                algo == SigningAlgo::Ed25519
            );
            let response_key = E2eeModelKey {
                signing_algo: algo,
                public_key: a.request.headers()["x-client-pub-key"]
                    .to_str()
                    .unwrap()
                    .to_owned(),
            };
            let response = json!({"id": "chat-1", "choices": [{"message": {
                "content": encrypt("only request A can read this", &response_key).unwrap()
            }}]})
            .to_string();
            assert_eq!(
                a.decrypt_json(response.as_bytes()).unwrap()["choices"][0]["message"]["content"],
                "only request A can read this"
            );
            assert_eq!(
                b.decrypt_json(response.as_bytes()).unwrap_err().code(),
                "e2ee.decryption_failed"
            );
        }
    }
    #[tokio::test]
    async fn decrypted_sse_releases_source_on_error_and_consumer_drop() {
        use futures_util::{Stream, StreamExt};
        use std::{
            pin::Pin,
            sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            },
            task::{Context, Poll},
        };
        struct Source {
            first: Option<Result<bytes::Bytes, InferenceError>>,
            dropped: Arc<AtomicUsize>,
        }
        impl Stream for Source {
            type Item = Result<bytes::Bytes, InferenceError>;
            fn poll_next(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                Poll::Ready(self.first.take())
            }
        }
        impl Drop for Source {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
        for case in [
            "consumer drop",
            "source error",
            "invalid UTF-8",
            "invalid JSON",
            "invalid ciphertext",
        ] {
            let (key, model_key) = fixed_key(SigningAlgo::Ed25519);
            let first = match case {
                "source error" => Err(protocol("test.source", "source failed").into()),
                "invalid UTF-8" => Ok(bytes::Bytes::from_static(b"data: \xff\n\n")),
                "invalid JSON" => Ok(bytes::Bytes::from_static(b"data: {\n\n")),
                _ => {
                    let content = if case == "invalid ciphertext" {
                        "bad".into()
                    } else {
                        encrypt("hello", &model_key).unwrap()
                    };
                    Ok(bytes::Bytes::from(format!(
                        "data: {}\n\n",
                        json!({"id":"chat-1","choices":[{"delta":{"content":content}}]})
                    )))
                }
            };
            let dropped = Arc::new(AtomicUsize::new(0));
            let source = Box::pin(Source {
                first: Some(first),
                dropped: dropped.clone(),
            });
            let prepared = PreparedE2eeChatRequest {
                request: reqwest::Request::new(
                    reqwest::Method::POST,
                    "https://example.com".parse().unwrap(),
                ),
                key,
            };
            let mut output = prepared.decrypt_sse(source);
            let result = output.next().await.unwrap();
            if case == "consumer drop" {
                assert!(String::from_utf8(result.unwrap().to_vec())
                    .unwrap()
                    .contains("hello"));
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
            } else {
                assert_eq!(
                    result.unwrap_err().code(),
                    match case {
                        "source error" => "test.source",
                        "invalid ciphertext" => "e2ee.decryption_failed",
                        _ => "api.invalid_response",
                    }
                );
                assert!(output.next().await.is_none(), "{case}");
            }
            drop(output);
            assert_eq!(dropped.load(Ordering::SeqCst), 1, "{case}");
        }
    }
    #[tokio::test]
    async fn decrypts_fragmented_sse_and_preserves_controls_and_newlines() {
        use futures_util::StreamExt;
        let (key, model) = fixed_key(SigningAlgo::Ed25519);
        let ciphertext = encrypt("🌍", &model).unwrap();
        let source=format!(": heartbeat\r\nid: event-1\r\nevent: message\r\ndata: {{\"id\":\"chat-1\",\r\ndata: \"choices\":[{{\"delta\":{{\"content\":\"{ciphertext}\"}}}}]}}\r\n\r\ndata: [DONE]\n\n: tail");
        let raw = source.as_bytes().to_vec();
        let input = Box::pin(futures_util::stream::iter(
            raw.into_iter().map(|b| Ok(bytes::Bytes::from(vec![b]))),
        ));
        let prepared = PreparedE2eeChatRequest {
            request: reqwest::Request::new(
                reqwest::Method::POST,
                "https://example.com".parse().unwrap(),
            ),
            key,
        };
        let mut output = prepared.decrypt_sse(input);
        let mut bytes = Vec::new();
        while let Some(chunk) = output.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        let output = String::from_utf8(bytes).unwrap();
        assert!(output.starts_with(": heartbeat\r\nid: event-1\r\nevent: message\r\ndata: "));
        assert!(output.contains("🌍"));
        assert!(output.ends_with("\r\n\r\ndata: [DONE]\n\n: tail"));
    }
}
