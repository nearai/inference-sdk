//! Verified Gateway inference APIs and deployment admission.
use crate::*;
use crate::{
    e2ee::remove_e2ee_headers,
    errors::protocol,
    inference_core::{
        input, ordinary_client, verified_at, CoreOptions, EvidenceApi, InferenceCore,
        PolicyVerifier, Session, SessionProvider, VerifiedReceipt,
    },
};
use futures_util::future::try_join_all;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
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
        let options = CoreOptions::default();
        Self {
            api_key: options.api_key,
            base_url: options.base_url,
            headers: options.headers,
            e2ee: options.e2ee,
            ohttp: options.ohttp,
            signing_algo: options.signing_algo,
            attestation_cache_ttl: options.attestation_cache_ttl,
            response_cache_ttl: options.response_cache_ttl,
            gateway_verification: GatewayVerificationOptions::default(),
            model_verification: options.model_verification,
            deployment_policy: options.deployment_policy,
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
    /// Report used to select the request's model public key, retained for compatibility.
    /// It does not identify which instance served the request.
    #[deprecated(
        note = "Use VerifiedCompletionResult::attestations for all verified reports sharing the selected model signer."
    )]
    Model(VerifiedModelAttestation),
}
/// A Gateway client's verified completion receipt.
#[derive(Clone, Debug)]
pub struct VerifiedCompletionResult {
    pub id: String,
    pub signature: CompletionSignature,
    /// Gateway evidence or the deprecated single-model representative.
    /// For model receipts, use [`Self::attestations`].
    pub attestation: VerifiedCompletionAttestation,
    /// Every verified Gateway model report sharing this response's signer.
    /// Empty for Gateway-signed receipts.
    pub attestations: Vec<VerifiedModelAttestation>,
}
impl VerifiedCompletionResult {
    pub fn signature_kind(&self) -> CompletionSignatureKind {
        self.signature.kind
    }
}
impl From<InferenceClientOptions> for CoreOptions {
    fn from(options: InferenceClientOptions) -> Self {
        Self {
            api_key: options.api_key,
            base_url: options.base_url,
            headers: options.headers,
            e2ee: options.e2ee,
            ohttp: options.ohttp,
            signing_algo: options.signing_algo,
            attestation_cache_ttl: options.attestation_cache_ttl,
            response_cache_ttl: options.response_cache_ttl,
            model_verification: options.model_verification,
            deployment_policy: options.deployment_policy,
        }
    }
}
#[derive(Clone)]
pub struct InferenceClient {
    core: InferenceCore,
}
impl InferenceClient {
    pub fn new(api_key: impl Into<Option<String>>) -> Result<Self, InferenceError> {
        Self::with_options(InferenceClientOptions {
            api_key: api_key.into(),
            ..Default::default()
        })
    }
    pub fn with_options(options: InferenceClientOptions) -> Result<Self, InferenceError> {
        let provider = SessionProvider::Gateway(options.gateway_verification.clone());
        Ok(Self {
            core: InferenceCore::new(options.into(), provider)?,
        })
    }
    pub fn base_url(&self) -> &str {
        self.core.base_url()
    }
    /// Release captured responses across all clones; keep the client reusable.
    pub async fn clear_response_cache(&self) {
        self.core.clear_response_cache().await;
    }
    /// Gateway and model evidence; cache hits preserve the original verification time.
    pub async fn verify(
        &self,
        model: &str,
    ) -> Result<AttestationVerificationResult, InferenceError> {
        let session = self.core.session(model).await?;
        Ok(AttestationVerificationResult {
            gateway: session
                .gateway
                .clone()
                .ok_or_else(|| input("client", "expected Gateway client"))?,
            models: session.models.clone(),
            verified_at: session.verified_at,
        })
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
        let generation = self.core.response_generation().await;
        let options = self.core.options();
        if options.e2ee || options.ohttp {
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
        let session = self.core.session(model).await?;
        if let Some(model_key) = session.model_key() {
            owned.insert(
                "x-model-pub-key",
                HeaderValue::from_str(&model_key.public_key)
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
        self.core
            .register(decision_id.clone(), body, bytes, session, false, generation)
            .await?;
        Ok(crate::SystemOneResult { data, decision_id })
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
        self.core.json_request("responses", body)
    }
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
        self.core.json_request("messages", body)
    }
    pub async fn verify_response(
        &self,
        id: &str,
    ) -> Result<VerifiedCompletionResult, InferenceError> {
        match self.core.verify_receipt(id).await? {
            VerifiedReceipt::Gateway(receipt) => Ok(*receipt),
            VerifiedReceipt::Direct(_) => unreachable!("Gateway client contains a Direct receipt"),
        }
    }
    /// OpenAI-compatible JSON Chat request. Use `send` for streaming.
    pub async fn chat_completions(&self, body: Value) -> Result<Value, InferenceError> {
        self.core.chat_completions(body).await
    }
    pub fn chat_request(&self, body: Value) -> Result<reqwest::Request, InferenceError> {
        self.core.chat_request(body)
    }
    /// Send an admitted Gateway request and retain its exact response bytes.
    pub async fn send(
        &self,
        request: reqwest::Request,
    ) -> Result<InferenceResponse, InferenceError> {
        self.core.send(request).await
    }
}
pub(crate) async fn create_session(
    model: &str,
    options: CoreOptions,
    gateway_options: GatewayVerificationOptions,
) -> Result<Arc<Session>, InferenceError> {
    let api = AttestationClient::with_base_url(options.api_key.clone(), &options.base_url)?
        .with_headers(options.headers.clone());
    let fetched = api
        .fetch_gateway_attestation(GatewayAttestationFetchOptions {
            signing_algo: Some(options.signing_algo),
            include_spki_fingerprint: gateway_options.include_spki_fingerprint,
        })
        .await?;
    let client = if gateway_options.include_spki_fingerprint {
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
        let o = &gateway_options;
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
    let model_attestations = async {
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
    // Authenticate the Gateway before sending configured credentials to it.
    let (gateway, ohttp) = gateway.await?;
    let model_attestations = model_attestations.await?;
    let selected_model_attestation = model_attestations
        .iter()
        .find(|model_attestation| {
            model_attestation.evidence.signer.signing_algo == options.signing_algo
                && model_attestation.signing_public_key.is_some()
        })
        .cloned();
    if !model_attestations.is_empty() && selected_model_attestation.is_none() {
        return Err(protocol(
            "e2ee.model_public_key_required",
            "no matching verified model public key",
        )
        .into());
    }
    Ok(Arc::new(Session {
        gateway: Some(gateway),
        models: model_attestations,
        selected: selected_model_attestation,
        direct: None,
        verified_at: verified_at(),
        client,
        api: EvidenceApi::Gateway(api),
        ohttp,
    }))
}
