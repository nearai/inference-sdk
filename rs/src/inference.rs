//! Verified Gateway Chat, shared admission checks, and exact-byte receipts.
use crate::*;
use crate::{
    e2ee::{decode_request, decrypt_response, invalid_response, remove_e2ee_headers},
    errors::protocol,
};
use futures_util::{
    future::{try_join_all, BoxFuture, Shared, WeakShared},
    FutureExt, Stream, StreamExt,
};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    StatusCode,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

pub type ByteStream = Pin<Box<dyn Stream<Item = Result<bytes::Bytes, InferenceError>> + Send>>;
/// Consume the entire body (including the EOF after SSE [DONE]) before verification.
pub struct InferenceResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: ByteStream,
}
impl InferenceResponse {
    pub async fn bytes(mut self) -> Result<Vec<u8>, InferenceError> {
        let mut bytes = Vec::new();
        while let Some(chunk) = self.body.next().await {
            bytes.extend_from_slice(&chunk?);
        }
        Ok(bytes)
    }
    pub async fn json(self) -> Result<Value, InferenceError> {
        serde_json::from_slice(&self.bytes().await?).map_err(|_| invalid_response().into())
    }
}
#[derive(Clone)]
pub struct GatewayVerificationOptions {
    pub include_spki_fingerprint: bool,
    pub policy: Option<AttestationPolicy>,
    pub tdx_quote: Option<Arc<dyn TdxQuoteVerifier>>,
    pub deployment: Option<Arc<dyn DeploymentVerifier>>,
}
impl Default for GatewayVerificationOptions {
    fn default() -> Self {
        Self {
            include_spki_fingerprint: true,
            policy: None,
            tdx_quote: None,
            deployment: None,
        }
    }
}
#[derive(Clone, Default)]
pub struct ModelVerificationOptions {
    pub policy: Option<ModelAttestationPolicy>,
    pub tdx_quote: Option<Arc<dyn TdxQuoteVerifier>>,
    pub gpu_evidence: Option<Arc<dyn GpuEvidenceVerifier>>,
    pub deployment: Option<Arc<dyn DeploymentVerifier>>,
}
#[async_trait::async_trait]
pub trait DeploymentPolicy: Send + Sync {
    async fn verify(
        &self,
        model: &str,
        deployment: &MeasuredDeployment,
    ) -> Result<(), VerificationError>;
}
#[derive(Clone)]
pub struct InferenceClientOptions {
    pub api_key: Option<String>,
    pub base_url: String,
    pub headers: HeaderMap,
    pub e2ee: bool,
    pub ohttp: bool,
    pub signing_algo: SigningAlgo,
    pub attestation_cache_ttl: Duration,
    pub response_cache_ttl: Duration,
    pub gateway_verification: GatewayVerificationOptions,
    pub model_verification: ModelVerificationOptions,
    pub deployment_policy: Option<Arc<dyn DeploymentPolicy>>,
}
impl Default for InferenceClientOptions {
    fn default() -> Self {
        Self {
            api_key: None,
            base_url: DEFAULT_NEAR_AI_CLOUD_BASE_URL.into(),
            headers: HeaderMap::new(),
            e2ee: false,
            ohttp: false,
            signing_algo: SigningAlgo::Ed25519,
            attestation_cache_ttl: Duration::from_secs(3600),
            response_cache_ttl: Duration::from_secs(3600),
            gateway_verification: GatewayVerificationOptions::default(),
            model_verification: ModelVerificationOptions::default(),
            deployment_policy: None,
        }
    }
}
#[derive(Clone, Debug)]
pub struct AttestationVerificationResult {
    pub gateway: VerifiedGatewayAttestation,
    pub models: Vec<VerifiedModelAttestation>,
    pub verified_at: u64,
}
#[derive(Clone, Debug)]
pub enum VerifiedCompletionAttestation {
    Gateway(VerifiedGatewayAttestation),
    Model(VerifiedModelAttestation),
    Direct(Vec<crate::direct::VerifiedDirectModelAttestation>),
}
#[derive(Clone, Debug)]
pub struct VerifiedCompletionResult {
    pub id: String,
    pub signature: CompletionSignature,
    pub attestation: VerifiedCompletionAttestation,
}
impl VerifiedCompletionResult {
    pub fn signature_kind(&self) -> CompletionSignatureKind {
        self.signature.kind
    }
}
#[derive(Clone)]
pub(crate) enum EvidenceApi {
    Gateway(AttestationClient),
    Direct(crate::direct::DirectAttestationClient),
}
impl EvidenceApi {
    async fn signature(
        &self,
        id: &str,
        algo: SigningAlgo,
    ) -> Result<CompletionSignature, ApiError> {
        match self {
            Self::Gateway(api) => api.fetch_completion_signature(id, Some(algo)).await,
            Self::Direct(api) => api.fetch_completion_signature(id, Some(algo)).await,
        }
    }
}
pub(crate) struct Session {
    pub gateway: Option<VerifiedGatewayAttestation>,
    pub models: Vec<VerifiedModelAttestation>,
    pub selected: Option<VerifiedModelAttestation>,
    pub direct: Option<crate::direct::DirectAttestationVerificationResult>,
    pub verified_at: u64,
    pub client: reqwest::Client,
    pub api: EvidenceApi,
    pub ohttp: Option<crate::OhttpClient>,
}
impl Session {
    fn model_key(&self) -> Option<E2eeModelKey> {
        self.selected.as_ref().and_then(|m| {
            m.signing_public_key.as_ref().map(|key| E2eeModelKey {
                signing_algo: m.evidence.signer.signing_algo,
                public_key: key.clone(),
            })
        })
    }
}
type PendingSession = WeakShared<BoxFuture<'static, Result<Arc<Session>, InferenceError>>>;
type ReceiptFuture = Shared<BoxFuture<'static, Result<VerifiedCompletionResult, InferenceError>>>;
struct Record {
    request: Arc<[u8]>,
    response: Arc<[u8]>,
    session: Arc<Session>,
    gateway_only: bool,
    finished: Instant,
    verification: Mutex<Option<ReceiptFuture>>,
}
#[derive(Default)]
struct State {
    sessions: HashMap<String, (Instant, Arc<Session>)>,
    pending: HashMap<String, PendingSession>,
    responses: HashMap<String, Arc<Record>>,
}
struct Inner {
    options: InferenceClientOptions,
    direct: bool,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct InferenceClient {
    inner: Arc<Inner>,
}
impl InferenceClient {
    pub fn new(api_key: impl Into<Option<String>>) -> Result<Self, InferenceError> {
        Self::with_options(InferenceClientOptions {
            api_key: api_key.into(),
            ..Default::default()
        })
    }
    pub fn with_options(options: InferenceClientOptions) -> Result<Self, InferenceError> {
        Self::create(options, false)
    }
    pub(crate) fn create(
        mut options: InferenceClientOptions,
        direct: bool,
    ) -> Result<Self, InferenceError> {
        options.base_url = crate::cloud_api::parse_base_url(&options.base_url)?.to_string();
        if options.ohttp && options.signing_algo != SigningAlgo::Ed25519 {
            return Err(input("signing_algo", "OHTTP requires Ed25519").into());
        }
        if let Some(key) = &options.api_key {
            options.headers.insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {key}"))
                    .map_err(|_| input("api_key", "invalid header"))?,
            );
            options.headers.remove("api-key");
        }
        Ok(Self {
            inner: Arc::new(Inner {
                options,
                direct,
                state: Mutex::new(State::default()),
            }),
        })
    }
    pub fn base_url(&self) -> &str {
        &self.inner.options.base_url
    }
    /// Gateway and model evidence; cache hits preserve the original verification time.
    pub async fn verify(
        &self,
        model: &str,
    ) -> Result<AttestationVerificationResult, InferenceError> {
        let session = self.session(model).await?;
        Ok(AttestationVerificationResult {
            gateway: session
                .gateway
                .clone()
                .ok_or_else(|| input("client", "expected Gateway client"))?,
            models: session.models.clone(),
            verified_at: session.verified_at,
        })
    }
    pub(crate) async fn session(&self, model: &str) -> Result<Arc<Session>, InferenceError> {
        let cache_key = model.to_owned();
        if model.is_empty() || matches!(model, "." | "..") {
            return Err(input("model", "expected a canonical model ID").into());
        }
        let options = &self.inner.options;
        let future = {
            let mut state = self.inner.state.lock().await;
            state
                .sessions
                .retain(|_, (time, _)| time.elapsed() < options.attestation_cache_ttl);
            if let Some((_, session)) = state.sessions.get(&cache_key) {
                return Ok(session.clone());
            }
            state.pending.retain(|_, f| f.upgrade().is_some());
            if let Some(future) = state.pending.get(&cache_key).and_then(|f| f.upgrade()) {
                future
            } else {
                let owned = model.to_owned();
                let options = options.clone();
                let direct = self.inner.direct;
                let future = async move {
                    if direct {
                        crate::direct::create_session(&owned, options).await
                    } else {
                        create_session(&owned, options).await
                    }
                }
                .boxed()
                .shared();
                state
                    .pending
                    .insert(cache_key.clone(), future.downgrade().expect("live future"));
                future
            }
        };
        let result = future.clone().await;
        let mut state = self.inner.state.lock().await;
        if state
            .pending
            .get(&cache_key)
            .and_then(|f| f.upgrade())
            .is_some_and(|f| f.ptr_eq(&future))
        {
            state.pending.remove(&cache_key);
            if let Ok(session) = &result {
                if !options.attestation_cache_ttl.is_zero() {
                    state
                        .sessions
                        .insert(cache_key.clone(), (Instant::now(), session.clone()));
                }
            }
        }
        result
    }
    /// Send one plaintext System One decision and retain exact bytes for verify_response.
    pub async fn systemone_create<T: serde::Serialize>(
        &self,
        request: &T,
    ) -> Result<crate::SystemOneResult, InferenceError> {
        self.systemone_create_with_headers(request, HeaderMap::new())
            .await
    }
    pub async fn systemone_create_with_headers<T: serde::Serialize>(
        &self,
        request: &T,
        headers: HeaderMap,
    ) -> Result<crate::SystemOneResult, InferenceError> {
        let options = &self.inner.options;
        if self.inner.direct || options.e2ee || options.ohttp {
            return Err(input("systemone", "requires a plaintext Gateway client").into());
        }
        let body =
            serde_json::to_vec(request).map_err(|_| input("systemone", "expected JSON request"))?;
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| input("systemone", "expected JSON object"))?;
        if !value.is_object() || value.get("stream").is_some() {
            return Err(input("systemone", "streaming is unsupported").into());
        }
        let model = value
            .get("model")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| input("model", "missing model"))?;
        let mut owned = options.headers.clone();
        owned.extend(headers);
        for name in ["authorization", "api-key"] {
            owned.remove(name);
            if let Some(value) = options.headers.get(name) {
                owned.insert(name, value.clone());
            }
        }
        remove_e2ee_headers(&mut owned);
        for name in [
            "host",
            "content-length",
            "content-encoding",
            "transfer-encoding",
            "trailer",
            "content-md5",
            "digest",
            "content-digest",
            "repr-digest",
        ] {
            owned.remove(name);
        }
        owned.insert(NO_ALIASING_HEADER, HeaderValue::from_static("true"));
        owned.insert("content-type", HeaderValue::from_static("application/json"));
        owned.insert("accept", HeaderValue::from_static("application/json"));
        owned.insert("accept-encoding", HeaderValue::from_static("identity"));
        let session = self.session(model).await?;
        if let Some(model) = session.model_key() {
            owned.insert(
                "x-model-pub-key",
                HeaderValue::from_str(&model.public_key)
                    .map_err(|_| input("model_key", "invalid header"))?,
            );
        }
        let url = crate::cloud_api::parse_base_url(self.base_url())?
            .join("systemone")
            .map_err(|_| input("base_url", "invalid URL"))?;
        let mut response = session
            .client
            .post(url)
            .headers(owned)
            .body(body.clone())
            .send()
            .await
            .map_err(|_| ApiError::Transport {
                resource: ApiResource::SystemOne,
                reason: ApiTransportReason::Request,
            })?;
        if !response.status().is_success() {
            return Err(ApiError::HttpStatus {
                resource: ApiResource::SystemOne,
                status: response.status().as_u16(),
            }
            .into());
        }
        let decision_id = response
            .headers()
            .get("x-generation-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ApiError::InvalidResponse {
                path: "systemone.x-generation-id".into(),
                expected: "nonempty receipt ID".into(),
                actual: "missing or invalid".into(),
            })?
            .to_owned();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::Transport {
            resource: ApiResource::SystemOne,
            reason: ApiTransportReason::ResponseBody,
        })? {
            bytes.extend_from_slice(&chunk);
        }
        let data = crate::systemone::decode_response(&bytes)?;
        self.register(decision_id.clone(), body, bytes, session, false)
            .await?;
        Ok(crate::SystemOneResult { data, decision_id })
    }
    /// OpenAI-compatible JSON Chat request. Use `send` for a byte-stream response.
    pub async fn chat_completions(&self, body: Value) -> Result<Value, InferenceError> {
        if body.get("stream") == Some(&Value::Bool(true)) {
            return Err(input("stream", "use send for streaming Chat").into());
        }
        let request = self.chat_request(body)?;
        let response = self.send(request).await?;
        if !response.status.is_success() {
            return Err(ApiError::HttpStatus {
                resource: ApiResource::Completion,
                status: response.status.as_u16(),
            }
            .into());
        }
        response.json().await
    }
    pub fn chat_request(&self, body: Value) -> Result<reqwest::Request, InferenceError> {
        self.json_request("chat/completions", body)
    }
    /// Create a Gateway Response and retain its bytes for `verify_response`.
    /// Use `response_request` and `send` for streaming responses.
    pub async fn create_response(&self, body: Value) -> Result<Value, InferenceError> {
        if body.get("stream") == Some(&Value::Bool(true)) {
            return Err(input("stream", "use send for streaming Responses").into());
        }
        let response = self.send(self.response_request(body)?).await?;
        if !response.status.is_success() {
            return Err(ApiError::HttpStatus {
                resource: ApiResource::Completion,
                status: response.status.as_u16(),
            }
            .into());
        }
        response.json().await
    }
    /// Build a Responses creation request. `send` performs preflight and capture.
    pub fn response_request(&self, body: Value) -> Result<reqwest::Request, InferenceError> {
        self.json_request("responses", body)
    }
    /* Messages support is deferred until a later release.
    /// Create an Anthropic Message and retain its bytes for `verify_response`.
    /// Use `message_request` and `send` for streaming events.
    pub async fn create_message(&self, body: Value) -> Result<Value, InferenceError> {
        if body.get("stream") == Some(&Value::Bool(true)) {
            return Err(input("stream", "use send for streaming Messages").into());
        }
        let response = self.send(self.message_request(body)?).await?;
        if !response.status.is_success() {
            return Err(ApiError::HttpStatus {
                resource: ApiResource::Completion,
                status: response.status.as_u16(),
            }
            .into());
        }
        response.json().await
    }
    /// Build a Messages creation request. `send` performs preflight and capture.
    pub fn message_request(&self, body: Value) -> Result<reqwest::Request, InferenceError> {
        self.json_request("messages", body)
    }
    */
    fn json_request(&self, path: &str, body: Value) -> Result<reqwest::Request, InferenceError> {
        let url = crate::cloud_api::parse_base_url(self.base_url())?
            .join(path)
            .map_err(|_| input("base_url", "invalid URL"))?;
        let mut request = reqwest::Request::new(reqwest::Method::POST, url);
        *request.body_mut() = Some(body.to_string().into());
        request
            .headers_mut()
            .insert("content-type", HeaderValue::from_static("application/json"));
        Ok(request)
    }
    /// Transport adapter for Chat and Responses requests. Authentication
    /// is always supplied by this client, including evidence and signature calls.
    pub async fn send(
        &self,
        mut request: reqwest::Request,
    ) -> Result<InferenceResponse, InferenceError> {
        let mut actual = request.url().clone();
        actual.set_query(None);
        let expected = crate::cloud_api::parse_base_url(self.base_url())?
            .join("chat/completions")
            .map_err(|_| input("base_url", "invalid URL"))?;
        let responses = actual
            == crate::cloud_api::parse_base_url(self.base_url())?
                .join("responses")
                .map_err(|_| input("base_url", "invalid URL"))?;
        let messages = actual
            == crate::cloud_api::parse_base_url(self.base_url())?
                .join("messages")
                .map_err(|_| input("base_url", "invalid URL"))?;
        // Messages support is deferred until a later release.
        // let gateway_only = responses || messages;
        let gateway_only = responses;
        if actual != expected && !gateway_only {
            return Err(input(
                "request.url",
                "expected configured inference creation endpoint",
            )
            .into());
        }
        if gateway_only && (self.inner.direct || self.inner.options.e2ee) {
            return Err(input(
                "request",
                "Responses require a Gateway client with field-level E2EE disabled",
            )
            .into());
        }
        let parsed = decode_request(&request)?;
        let session = self
            .session(
                parsed["model"]
                    .as_str()
                    .ok_or_else(|| input("model", "missing model"))?,
            )
            .await?;
        let options = &self.inner.options;
        let mut headers = options.headers.clone();
        headers.extend(request.headers().clone());
        headers.remove("authorization");
        if let Some(value) = options.headers.get("authorization") {
            headers.insert("authorization", value.clone());
        }
        headers.remove("api-key");
        if let Some(value) = options.headers.get("api-key") {
            headers.insert("api-key", value.clone());
        }
        if messages {
            headers.remove("x-api-key");
            if let Some(value) = options.headers.get("x-api-key") {
                headers.insert("x-api-key", value.clone());
            }
            headers
                .entry("anthropic-version")
                .or_insert(HeaderValue::from_static("2023-06-01"));
        }
        headers.insert("accept-encoding", HeaderValue::from_static("identity"));
        headers.remove("host");
        headers.remove("transfer-encoding");
        headers.remove("trailer");
        *request.headers_mut() = headers;
        let key = if options.e2ee {
            let model = session.model_key().ok_or_else(|| {
                protocol(
                    "policy.model_attestation_required",
                    "E2EE requires model evidence",
                )
            })?;
            let prepared = prepare_e2ee_chat_request(request, &model)?;
            request = prepared.request;
            Some(prepared.key)
        } else {
            remove_e2ee_headers(request.headers_mut());
            request
                .headers_mut()
                .insert(NO_ALIASING_HEADER, HeaderValue::from_static("true"));
            if let Some(model) = session.model_key().filter(|_| !messages) {
                request.headers_mut().insert(
                    "x-model-pub-key",
                    HeaderValue::from_str(&model.public_key)
                        .map_err(|_| input("model_key", "invalid header"))?,
                );
            }
            None
        };
        let request_body = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .ok_or_else(|| input("body", "buffered body required"))?
            .to_vec();
        let response = if let Some(ohttp) = &session.ohttp {
            ohttp.send(request).await?
        } else {
            let response = session
                .client
                .execute(request)
                .await
                .map_err(|_| transport(ApiTransportReason::Request))?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = Box::pin(
                response
                    .bytes_stream()
                    .map(|r| r.map_err(|_| transport(ApiTransportReason::ResponseBody).into())),
            );
            InferenceResponse {
                status,
                headers,
                body,
            }
        };
        if !response.status.is_success() {
            return Ok(response);
        }
        let streaming = response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.to_ascii_lowercase().starts_with("text/event-stream"));
        let mut headers = response.headers;
        for name in [
            "content-length",
            "content-encoding",
            "etag",
            "content-md5",
            "digest",
            "content-digest",
            "repr-digest",
            "last-modified",
        ] {
            headers.remove(name);
        }
        let mut source = response.body;
        let owner = self.clone();
        let stream = async_stream::try_stream! {
            let mut wire = Vec::new();
            let mut decoder = crate::sse::SseDecoder::default();
            let mut id = None;
            let mut message_state = crate::sse::MessageStreamState::default();
            let mut first_record = true;
            let mut transform_record = |record: Vec<u8>| -> Result<Vec<u8>, InferenceError> {
                let parsed = if std::mem::replace(&mut first_record, false) {
                    record.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&record)
                } else {
                    &record
                };
                if messages { message_state.observe(parsed)?; }
                let transformed = crate::sse::transform(parsed, key.as_ref(), &mut id, responses, messages)?;
                // The retained signature payload and plaintext output keep the BOM.
                Ok(if key.is_some() { transformed } else { record })
            };
            while let Some(chunk) = source.next().await {
                let chunk = chunk?;
                wire.extend_from_slice(&chunk);
                if streaming {
                    for record in decoder.push(&chunk, false) {
                        yield bytes::Bytes::from(transform_record(record)?);
                    }
                }
            }
            if streaming {
                for record in decoder.push(&[], true) {
                    yield bytes::Bytes::from(transform_record(record)?);
                }
                let id = id.ok_or_else(invalid_response)?;
                if messages { message_state.finish()?; }
                owner.register(id, request_body, wire, session, gateway_only).await?;
            } else {
                let mut value: Value = serde_json::from_slice(&wire).map_err(|_| invalid_response())?;
                let id = value
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(invalid_response)?
                    .to_owned();
                if let Some(key) = key.as_ref() {
                    decrypt_response(&mut value, key, false)?;
                }
                let body = if key.is_some() {
                    value.to_string().into_bytes()
                } else {
                    wire.clone()
                };
                owner.register(id, request_body, wire, session, gateway_only).await?;
                yield bytes::Bytes::from(body);
            }
        };
        Ok(InferenceResponse {
            status: response.status,
            headers,
            body: Box::pin(stream),
        })
    }
    pub(crate) async fn register(
        &self,
        id: String,
        request: Vec<u8>,
        response: Vec<u8>,
        session: Arc<Session>,
        gateway_only: bool,
    ) -> Result<(), InferenceError> {
        let options = &self.inner.options;
        let mut state = self.inner.state.lock().await;
        state
            .responses
            .retain(|_, r| r.finished.elapsed() < options.response_cache_ttl);
        if options.response_cache_ttl.is_zero() {
            return Ok(());
        }
        // Never let a repeated ID replace the evidence/bytes of another completion.
        if state.responses.contains_key(&id) {
            return Err(ApiError::DuplicateCompletionId.into());
        }
        state.responses.insert(
            id,
            Arc::new(Record {
                request: request.into(),
                response: response.into(),
                session,
                gateway_only,
                finished: Instant::now(),
                verification: Mutex::new(None),
            }),
        );
        Ok(())
    }
    pub async fn verify_response(
        &self,
        id: &str,
    ) -> Result<VerifiedCompletionResult, InferenceError> {
        let record = {
            let mut state = self.inner.state.lock().await;
            state
                .responses
                .retain(|_, r| r.finished.elapsed() < self.inner.options.response_cache_ttl);
            state
                .responses
                .get(id)
                .cloned()
                .ok_or(ApiError::CompletionNotFound)?
        };
        let future = {
            let mut pending = record.verification.lock().await;
            if pending.is_none() {
                // Do not capture Record itself: the cached future must not form an Arc cycle.
                let request = record.request.clone();
                let response = record.response.clone();
                let session = record.session.clone();
                let gateway_only = record.gateway_only;
                let id = id.to_owned();
                let algo = self.inner.options.signing_algo;
                *pending = Some(
                    async move {
                        let signature = session.api.signature(&id, algo).await?;
                        if signature.signer.signing_algo != algo {
                            return Err(VerificationError::SignatureSignerMismatch.into());
                        }
                        if gateway_only && signature.kind != CompletionSignatureKind::Gateway {
                            return Err(VerificationError::SignatureKindMismatch {
                                expected: CompletionSignatureKind::Gateway,
                                actual: signature.kind,
                            }
                            .into());
                        }
                        let attestation = match signature.kind {
                            CompletionSignatureKind::Gateway => {
                                let gateway = session.gateway.as_ref().ok_or(
                                    VerificationError::SignatureKindMismatch {
                                        expected: CompletionSignatureKind::ProviderTee,
                                        actual: signature.kind,
                                    },
                                )?;
                                verify_gateway_response(&request, &response, &signature, gateway)?;
                                VerifiedCompletionAttestation::Gateway(gateway.clone())
                            }
                            CompletionSignatureKind::ProviderTee => {
                                let model = session.selected.as_ref().ok_or(
                                    VerificationError::SignatureKindMismatch {
                                        expected: CompletionSignatureKind::Gateway,
                                        actual: signature.kind,
                                    },
                                )?;
                                verify_model_response(&request, &response, &signature, model)?;
                                if let Some(direct) = &session.direct {
                                    let matching = direct
                                        .attestations
                                        .iter()
                                        .filter(|a| {
                                            crate::direct::same_signer(
                                                &a.attestation.evidence.signer,
                                                &model.evidence.signer,
                                            )
                                        })
                                        .cloned()
                                        .collect();
                                    VerifiedCompletionAttestation::Direct(matching)
                                } else {
                                    VerifiedCompletionAttestation::Model(model.clone())
                                }
                            }
                        };
                        Ok(VerifiedCompletionResult {
                            id,
                            signature,
                            attestation,
                        })
                    }
                    .boxed()
                    .shared(),
                );
            }
            pending.as_ref().expect("initialized future").clone()
        };
        let result = future.clone().await;
        if result
            .as_ref()
            .err()
            .is_some_and(|e| e.retryable() || e.code() == "api.completion_signature_unavailable")
        {
            let mut pending = record.verification.lock().await;
            if pending.as_ref().is_some_and(|f| f.ptr_eq(&future)) {
                *pending = None;
            }
        }
        result
    }
}
pub(crate) fn input(field: &str, reason: &str) -> ApiError {
    ApiError::InvalidInput {
        field: field.into(),
        reason: reason.into(),
        expected: None,
        actual: None,
    }
}
fn transport(reason: ApiTransportReason) -> ApiError {
    ApiError::Transport {
        resource: ApiResource::Completion,
        reason,
    }
}
pub(crate) fn verified_at() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub(crate) fn ordinary_client() -> Result<reqwest::Client, InferenceError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| input("client", "invalid HTTP configuration").into())
}
pub(crate) struct PolicyVerifier<'a> {
    pub model: &'a str,
    pub original: Option<&'a dyn DeploymentVerifier>,
    pub policy: Option<&'a dyn DeploymentPolicy>,
}
#[async_trait::async_trait]
impl DeploymentVerifier for PolicyVerifier<'_> {
    async fn verify(&self, deployment: &MeasuredDeployment) -> Result<(), VerificationError> {
        if let Some(v) = self.original {
            v.verify(deployment).await?;
        }
        if let Some(v) = self.policy {
            v.verify(self.model, deployment).await?;
        }
        Ok(())
    }
}
async fn create_session(
    model: &str,
    options: InferenceClientOptions,
) -> Result<Arc<Session>, InferenceError> {
    let api = AttestationClient::with_base_url(options.api_key.clone(), &options.base_url)?
        .with_headers(options.headers.clone());
    let fetched = api
        .fetch_gateway_attestation(GatewayAttestationFetchOptions {
            signing_algo: Some(options.signing_algo),
            include_spki_fingerprint: options.gateway_verification.include_spki_fingerprint,
        })
        .await?;
    let client = if options.gateway_verification.include_spki_fingerprint {
        let pin = fetched
            .client_binding
            .spki_fingerprint
            .as_ref()
            .ok_or(VerificationError::SpkiFingerprintRequired)?;
        create_pinned_tls_client(std::slice::from_ref(pin))?
    } else {
        ordinary_client()?
    };
    let api = api.with_http_client(client.clone());
    let gateway = async {
        let o = &options.gateway_verification;
        let result = verify_gateway_attestation(
            &fetched.attestation,
            &fetched.client_binding,
            o.policy.as_ref(),
            AttestationVerifiers {
                tdx_quote: o.tdx_quote.as_deref(),
                deployment: o.deployment.as_deref(),
            },
        )
        .await?;
        if result.evidence.signer.signing_algo != options.signing_algo {
            return Err(InferenceError::from(
                VerificationError::SignatureSignerMismatch,
            ));
        }
        let ohttp = if options.ohttp {
            let raw = fetched.ohttp_attestation.as_ref().ok_or_else(|| {
                protocol(
                    "ohttp.attestation_required",
                    "Gateway omitted OHTTP evidence",
                )
            })?;
            let config = verify_ohttp_key_config(raw, &result.evidence.signer)?;
            Some(create_ohttp_client(
                &config,
                &options.base_url,
                client.clone(),
                options.headers.keys().map(|k| k.to_string()).collect(),
            )?)
        } else {
            None
        };
        Ok((result, ohttp))
    };
    let models = async {
        let metadata = api.fetch_model_metadata(model).await?;
        let o = &options.model_verification;
        if metadata.provider_type != "vllm" || !metadata.attestation_supported {
            if options.e2ee
                || o.policy.is_some()
                || o.deployment.is_some()
                || options.deployment_policy.is_some()
            {
                return Err(protocol(
                    "policy.model_attestation_required",
                    "model does not support NEAR attestation",
                )
                .into());
            }
            return Ok(Vec::new());
        }
        let fetched = api
            .fetch_model_attestations(model, Some(options.signing_algo), None)
            .await?;
        if fetched.attestations.is_empty() {
            return Err(protocol(
                "policy.model_attestation_required",
                "no model reports returned",
            )
            .into());
        }
        let policy = PolicyVerifier {
            model,
            original: o.deployment.as_deref(),
            policy: options.deployment_policy.as_deref(),
        };
        let deployment = if o.deployment.is_some() || options.deployment_policy.is_some() {
            Some(&policy as &dyn DeploymentVerifier)
        } else {
            None
        };
        let results = try_join_all(fetched.attestations.iter().map(|report| {
            verify_model_attestation(
                report,
                &fetched.client_binding,
                o.policy.as_ref(),
                ModelAttestationVerifiers {
                    tdx_quote: o.tdx_quote.as_deref(),
                    gpu_evidence: o.gpu_evidence.as_deref(),
                    deployment,
                },
            )
        }))
        .await?;
        Ok::<_, InferenceError>(results)
    };
    let ((gateway, ohttp), models) = futures_util::try_join!(gateway, models)?;
    let selected = models
        .iter()
        .find(|m| {
            m.evidence.signer.signing_algo == options.signing_algo && m.signing_public_key.is_some()
        })
        .cloned();
    if !models.is_empty() && selected.is_none() {
        return Err(protocol(
            "e2ee.model_public_key_required",
            "no matching verified model public key",
        )
        .into());
    }
    Ok(Arc::new(Session {
        gateway: Some(gateway),
        models,
        selected,
        direct: None,
        verified_at: verified_at(),
        client,
        api: EvidenceApi::Gateway(api),
        ohttp,
    }))
}
