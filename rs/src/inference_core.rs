//! Shared inference transport, capture, cache, and receipt lifecycle.
use crate::*;
use crate::{
    e2ee::{decode_request, decrypt_response, invalid_response, remove_e2ee_headers},
    errors::protocol,
};
use futures_util::{
    future::{BoxFuture, Shared, WeakShared},
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
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

pub type ByteStream = Pin<Box<dyn Stream<Item = Result<bytes::Bytes, InferenceError>> + Send>>;
/// Consume the entire response body before verification.
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
pub(crate) struct CoreOptions {
    pub(crate) api_key: Option<String>,
    pub(crate) base_url: String,
    pub(crate) headers: HeaderMap,
    pub(crate) e2ee: bool,
    pub(crate) ohttp: bool,
    pub(crate) signing_algo: SigningAlgo,
    pub(crate) attestation_cache_ttl: Duration,
    pub(crate) response_cache_ttl: Duration,
    pub(crate) model_verification: ModelVerificationOptions,
    pub(crate) deployment_policy: Option<Arc<dyn DeploymentPolicy>>,
}
impl Default for CoreOptions {
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
            model_verification: ModelVerificationOptions::default(),
            deployment_policy: None,
        }
    }
}
#[derive(Clone)]
pub(crate) enum SessionProvider {
    Gateway(GatewayVerificationOptions),
    Direct { include_spki_fingerprint: bool },
}
impl SessionProvider {
    fn is_direct(&self) -> bool {
        matches!(self, Self::Direct { .. })
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
    pub(crate) fn model_key(&self) -> Option<E2eeModelKey> {
        self.selected.as_ref().and_then(|m| {
            m.signing_public_key.as_ref().map(|key| E2eeModelKey {
                signing_algo: m.evidence.signer.signing_algo,
                public_key: key.clone(),
            })
        })
    }
}
type PendingSession = WeakShared<BoxFuture<'static, Result<Arc<Session>, InferenceError>>>;
#[derive(Clone, Debug)]
pub(crate) enum VerifiedReceipt {
    Gateway(Box<VerifiedCompletionResult>),
    Direct(VerifiedDirectCompletionResult),
}
type ReceiptFuture = Shared<BoxFuture<'static, Result<VerifiedReceipt, InferenceError>>>;
struct Record {
    finished: Instant,
    // A synchronous lock prevents cancellation between terminal verification and capture release.
    state: StdMutex<RecordState>,
}
struct RecordState {
    captured: Option<CapturedResponse>,
    verification: Option<ReceiptFuture>,
}
struct CapturedResponse {
    request: Arc<[u8]>,
    response: Arc<[u8]>,
    session: Arc<Session>,
    gateway_only: bool,
}
#[derive(Default)]
struct State {
    sessions: HashMap<String, (Instant, Arc<Session>)>,
    pending: HashMap<String, PendingSession>,
    responses: HashMap<String, Arc<Record>>,
    response_generation: u64,
}
struct Inner {
    options: CoreOptions,
    provider: SessionProvider,
    state: Mutex<State>,
}
#[derive(Clone)]
pub(crate) struct InferenceCore {
    inner: Arc<Inner>,
}
impl InferenceCore {
    pub(crate) fn new(
        mut options: CoreOptions,
        provider: SessionProvider,
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
                provider,
                state: Mutex::new(State::default()),
            }),
        })
    }
    pub(crate) fn base_url(&self) -> &str {
        &self.inner.options.base_url
    }
    /// Clear captured response verification records.
    pub(crate) async fn clear_response_cache(&self) {
        let mut state = self.inner.state.lock().await;
        state.response_generation = state.response_generation.wrapping_add(1);
        state.responses.clear();
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
                let provider = self.inner.provider.clone();
                let future = async move {
                    match provider {
                        SessionProvider::Direct {
                            include_spki_fingerprint,
                        } => {
                            crate::direct::create_session(&owned, options, include_spki_fingerprint)
                                .await
                        }
                        SessionProvider::Gateway(verification) => {
                            crate::inference::create_session(&owned, options, verification).await
                        }
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
    /// OpenAI-compatible JSON Chat request. Use `send` for a byte-stream response.
    pub(crate) async fn chat_completions(&self, body: Value) -> Result<Value, InferenceError> {
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
    pub(crate) fn chat_request(&self, body: Value) -> Result<reqwest::Request, InferenceError> {
        self.json_request("chat/completions", body)
    }
    pub(crate) fn json_request(
        &self,
        path: &str,
        body: Value,
    ) -> Result<reqwest::Request, InferenceError> {
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
    /// Transport adapter for Chat, Responses, and Messages requests. Authentication
    /// is always supplied by this client, including evidence and signature calls.
    pub(crate) async fn send(
        &self,
        mut request: reqwest::Request,
    ) -> Result<InferenceResponse, InferenceError> {
        let generation = self.inner.state.lock().await.response_generation;
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
        let gateway_only = responses || messages;
        if actual != expected && !gateway_only {
            return Err(input(
                "request.url",
                "expected configured inference creation endpoint",
            )
            .into());
        }
        if gateway_only && (self.inner.provider.is_direct() || self.inner.options.e2ee) {
            return Err(input(
                "request",
                "Responses and Messages require a Gateway client with field-level E2EE disabled",
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
            let model_key = session.model_key().ok_or_else(|| {
                protocol(
                    "policy.model_attestation_required",
                    "E2EE requires model evidence",
                )
            })?;
            let prepared = prepare_e2ee_chat_request(request, &model_key)?;
            request = prepared.request;
            Some(prepared.key)
        } else {
            remove_e2ee_headers(request.headers_mut());
            request
                .headers_mut()
                .insert(NO_ALIASING_HEADER, HeaderValue::from_static("true"));
            if let Some(model_key) = session.model_key().filter(|_| !messages) {
                request.headers_mut().insert(
                    "x-model-pub-key",
                    HeaderValue::from_str(&model_key.public_key)
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
            let mode = if responses {
                crate::sse::SseMode::Responses
            } else if messages {
                crate::sse::SseMode::Messages
            } else {
                crate::sse::SseMode::Chat
            };
            let mut events = crate::sse::SseStream::new(mode);
            while let Some(chunk) = source.next().await {
                let chunk = chunk?;
                wire.extend_from_slice(&chunk);
                if streaming {
                    for record in decoder.push(&chunk, false) {
                        yield bytes::Bytes::from(events.transform(record, key.as_ref())?);
                    }
                }
            }
            if streaming {
                for record in decoder.push(&[], true) {
                    yield bytes::Bytes::from(events.transform(record, key.as_ref())?);
                }
                let id = events.finish()?;
                owner.register(id, request_body, wire, session, gateway_only, generation).await?;
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
                owner.register(id, request_body, wire, session, gateway_only, generation).await?;
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
        generation: u64,
    ) -> Result<(), InferenceError> {
        let options = &self.inner.options;
        let mut state = self.inner.state.lock().await;
        if generation != state.response_generation {
            return Ok(());
        }
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
                finished: Instant::now(),
                state: StdMutex::new(RecordState {
                    captured: Some(CapturedResponse {
                        request: request.into(),
                        response: response.into(),
                        session,
                        gateway_only,
                    }),
                    verification: None,
                }),
            }),
        );
        Ok(())
    }
    pub(crate) async fn verify_receipt(&self, id: &str) -> Result<VerifiedReceipt, InferenceError> {
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
            let mut state = record.state.lock().expect("response record mutex poisoned");
            if state.verification.is_none() {
                let captured = state.captured.as_ref().expect("unverified response bytes");
                // Do not capture Record itself: the cached future must not form an Arc cycle.
                let request = captured.request.clone();
                let response = captured.response.clone();
                let session = captured.session.clone();
                let gateway_only = captured.gateway_only;
                let id = id.to_owned();
                let algo = self.inner.options.signing_algo;
                state.verification = Some(
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
                        let mut attestations = Vec::new();
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
                                let selected_model_attestation = session.selected.as_ref().ok_or(
                                    VerificationError::SignatureKindMismatch {
                                        expected: CompletionSignatureKind::Gateway,
                                        actual: signature.kind,
                                    },
                                )?;
                                verify_model_response(
                                    &request,
                                    &response,
                                    &signature,
                                    selected_model_attestation,
                                )?;
                                if let Some(direct) = &session.direct {
                                    let matching_attestations = direct
                                        .attestations
                                        .iter()
                                        .filter(|a| {
                                            crate::direct::same_signer(
                                                &a.attestation.evidence.signer,
                                                &selected_model_attestation.evidence.signer,
                                            )
                                        })
                                        .cloned()
                                        .collect();
                                    return Ok(VerifiedReceipt::Direct(
                                        VerifiedDirectCompletionResult {
                                            id,
                                            signature,
                                            attestations: matching_attestations,
                                        },
                                    ));
                                } else {
                                    attestations = crate::find_model_attestations_for_signature(
                                        &session.models,
                                        &signature,
                                    )?
                                    .into_iter()
                                    .cloned()
                                    .collect();
                                    // Preserve the deprecated representative for existing callers.
                                    #[allow(deprecated)]
                                    let representative = VerifiedCompletionAttestation::Model(
                                        selected_model_attestation.clone(),
                                    );
                                    representative
                                }
                            }
                        };
                        Ok(VerifiedReceipt::Gateway(Box::new(
                            VerifiedCompletionResult {
                                id,
                                signature,
                                attestation,
                                attestations,
                            },
                        )))
                    }
                    .boxed()
                    .shared(),
                );
            }
            state
                .verification
                .as_ref()
                .expect("initialized future")
                .clone()
        };
        let result = future.clone().await;
        let retryable = result
            .as_ref()
            .err()
            .is_some_and(|e| e.retryable() || e.code() == "api.completion_signature_unavailable");
        let mut state = record.state.lock().expect("response record mutex poisoned");
        if state
            .verification
            .as_ref()
            .is_some_and(|f| f.ptr_eq(&future))
        {
            if retryable {
                state.verification = None;
            } else {
                // Cached terminal results no longer need the original wire bytes.
                state.captured = None;
            }
        }
        result
    }
    pub(crate) fn options(&self) -> &CoreOptions {
        &self.inner.options
    }
    pub(crate) async fn response_generation(&self) -> u64 {
        self.inner.state.lock().await.response_generation
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
#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::future::{poll_fn, Future};

    async fn captured_client() -> (InferenceCore, Arc<Record>) {
        let client = InferenceCore::new(
            CoreOptions::default(),
            SessionProvider::Gateway(GatewayVerificationOptions::default()),
        )
        .unwrap();
        let session = Arc::new(Session {
            gateway: None,
            models: Vec::new(),
            selected: None,
            direct: None,
            verified_at: 0,
            client: reqwest::Client::new(),
            api: EvidenceApi::Gateway(AttestationClient::new(None)),
            ohttp: None,
        });
        client
            .register(
                "receipt".into(),
                vec![1; 1024],
                vec![2; 1024],
                session,
                false,
                0,
            )
            .await
            .unwrap();
        let record = client.inner.state.lock().await.responses["receipt"].clone();
        (client, record)
    }

    fn verified_result() -> VerifiedReceipt {
        VerifiedReceipt::Direct(VerifiedDirectCompletionResult {
            id: "receipt".into(),
            signature: CompletionSignature {
                kind: CompletionSignatureKind::ProviderTee,
                signed_text: "fixture hashes".into(),
                signature: "fixture signature".into(),
                signer: SigningIdentity {
                    signing_algo: SigningAlgo::Ed25519,
                    signing_address: "fixture signer".into(),
                },
            },
            attestations: Vec::new(),
        })
    }

    fn receipt_id(receipt: &VerifiedReceipt) -> &str {
        match receipt {
            VerifiedReceipt::Gateway(receipt) => &receipt.id,
            VerifiedReceipt::Direct(receipt) => &receipt.id,
        }
    }

    #[tokio::test]
    async fn terminal_receipts_release_bytes_and_session_but_keep_result_and_expiry() {
        for result in [
            Ok(verified_result()),
            Err(VerificationError::SignatureSignerMismatch.into()),
        ] {
            let (client, record) = captured_client().await;
            let finished = record.finished;
            let (request, response, session) = {
                let mut state = record.state.lock().expect("response record mutex poisoned");
                let captured = state.captured.as_ref().unwrap();
                let refs = (
                    Arc::downgrade(&captured.request),
                    Arc::downgrade(&captured.response),
                    Arc::downgrade(&captured.session),
                );
                // Isolate retention from the cryptographic verification covered by integration tests.
                state.verification =
                    Some(futures_util::future::ready(result.clone()).boxed().shared());
                refs
            };
            for _ in 0..2 {
                let actual = client.verify_receipt("receipt").await;
                match &result {
                    Ok(expected) => assert_eq!(receipt_id(&actual.unwrap()), receipt_id(expected)),
                    Err(expected) => assert_eq!(actual.unwrap_err().code(), expected.code()),
                }
            }
            assert!(request.upgrade().is_none());
            assert!(response.upgrade().is_none());
            assert!(session.upgrade().is_none());
            assert_eq!(record.finished, finished);
            assert!(Arc::ptr_eq(
                &record,
                &client.inner.state.lock().await.responses["receipt"]
            ));
            client.clear_response_cache().await;
            assert_eq!(
                client.verify_receipt("receipt").await.unwrap_err().code(),
                "api.completion_not_found"
            );
        }
    }

    #[tokio::test]
    async fn terminal_capture_release_cannot_be_cancelled_after_verification() {
        for result in [
            Ok(verified_result()),
            Err(VerificationError::SignatureSignerMismatch.into()),
        ] {
            let (client, record) = captured_client().await;
            let terminal_result = result.clone();
            let verification = async move {
                // Finish verification with no cooperative budget left for an async lock.
                while tokio::task::coop::has_budget_remaining() {
                    tokio::task::coop::consume_budget().await;
                }
                terminal_result
            }
            .boxed()
            .shared();
            let (request, response, session) = {
                let mut state = record.state.lock().expect("response record mutex poisoned");
                let captured = state.captured.as_ref().unwrap();
                let refs = (
                    Arc::downgrade(&captured.request),
                    Arc::downgrade(&captured.response),
                    Arc::downgrade(&captured.session),
                );
                state.verification = Some(verification.clone());
                refs
            };
            let mut caller = Box::pin(client.verify_receipt("receipt"));
            // Dropping a pending caller models timeout/select cancellation at the yield point.
            let _ = poll_fn(|cx| std::task::Poll::Ready(caller.as_mut().poll(cx))).await;
            drop(caller);
            assert!(
                verification.peek().is_some(),
                "verification reached a terminal result"
            );
            assert!(
                request.upgrade().is_none(),
                "request retained after terminal verification"
            );
            assert!(response.upgrade().is_none());
            assert!(session.upgrade().is_none());
            let cached = client.verify_receipt("receipt").await;
            match result {
                Ok(expected) => assert_eq!(receipt_id(&cached.unwrap()), receipt_id(&expected)),
                Err(expected) => assert_eq!(cached.unwrap_err().code(), expected.code()),
            }
        }
    }

    #[tokio::test]
    async fn retryable_receipts_keep_bytes_for_a_later_lookup() {
        for error in [
            ApiError::HttpStatus {
                resource: ApiResource::CompletionSignature,
                status: 503,
            },
            ApiError::CompletionSignatureUnavailable {
                provider_error_code: "fixture".into(),
                provider_message: "not ready".into(),
            },
        ] {
            let (client, record) = captured_client().await;
            let (request, response) = {
                let mut state = record.state.lock().expect("response record mutex poisoned");
                let captured = state.captured.as_ref().unwrap();
                let refs = (
                    Arc::downgrade(&captured.request),
                    Arc::downgrade(&captured.response),
                );
                state.verification = Some(
                    futures_util::future::ready(Err(error.into()))
                        .boxed()
                        .shared(),
                );
                refs
            };
            client.verify_receipt("receipt").await.unwrap_err();
            assert!(record
                .state
                .lock()
                .expect("response record mutex poisoned")
                .verification
                .is_none());
            assert!(request.upgrade().is_some());
            assert!(response.upgrade().is_some());
            record
                .state
                .lock()
                .expect("response record mutex poisoned")
                .verification = Some(
                futures_util::future::ready(Ok(verified_result()))
                    .boxed()
                    .shared(),
            );
            client.verify_receipt("receipt").await.unwrap();
            assert!(request.upgrade().is_none());
            assert!(response.upgrade().is_none());
        }
    }
}
