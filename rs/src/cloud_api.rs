use crate::errors::{ApiError, ApiResource, ApiTransportReason, SdkError, VerificationError};
use crate::types::{
    AttestationEventLog, AttestationEvidence, CompletionSignature, CompletionSignatureKind,
    CompletionSignatureLookup, CompletionSignatureReference, FetchedGatewayAttestation,
    FetchedModelAttestation, FetchedModelAttestations, GatewayAttestation, GatewayClientBinding,
    ModelAttestation, SignatureUnavailable, SigningAlgo, SigningIdentity,
};
use crate::util::{decode_hex, generate_nonce, require_hex_length, sha256};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION},
    Client, Url,
};
use serde::{de::Error as _, Deserialize, Deserializer};
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};

/// Default production endpoint used when a helper does not select another one.
pub const DEFAULT_NEAR_AI_CLOUD_BASE_URL: &str = "https://cloud-api.near.ai/v1";

/// Set this on model-attestation requests to reject aliases before dispatch.
pub const NO_ALIASING_HEADER: &str = "x-no-aliasing";

/// Internal transport and endpoint settings owned by an individual request
/// builder. It is intentionally not a reusable client configuration type:
/// callers pass their API key to each operation they make.
struct CloudApiRequestConfig {
    api_key: String,
    base_url: Url,
    client: Client,
    gateway_client: Client,
}

impl CloudApiRequestConfig {
    fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: parse_base_url(DEFAULT_NEAR_AI_CLOUD_BASE_URL)
                .expect("the SDK's default Cloud API URL is valid"),
            client: Client::new(),
            // A Gateway TLS binding must observe the Gateway's own peer, not
            // a system-configured HTTPS proxy. Other Cloud API requests keep
            // reqwest's normal proxy behavior.
            gateway_client: Client::builder()
                .no_proxy()
                .tls_info(true)
                .build()
                .expect("the SDK's default HTTP client configuration is valid"),
        }
    }

    fn set_base_url(&mut self, base_url: impl AsRef<str>) -> Result<(), VerificationError> {
        self.base_url = parse_base_url(base_url.as_ref())?;
        Ok(())
    }

    fn endpoint(&self, path: &str) -> Result<Url, VerificationError> {
        self.base_url
            .join(path)
            .map_err(|_| VerificationError::InvalidInput {
                field: "base_url".to_owned(),
                reason: "cannot resolve API endpoint".to_owned(),
            })
    }
}

/// Build a request for NEAR model evidence. The builder starts with the
/// production endpoint; use its methods only when the request needs filters
/// or another endpoint.
pub struct ModelAttestationsRequest {
    config: CloudApiRequestConfig,
    model: String,
    signing_algo: Option<SigningAlgo>,
    signing_address: Option<String>,
}

impl ModelAttestationsRequest {
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            config: CloudApiRequestConfig::new(api_key),
            model: model.into(),
            signing_algo: None,
            signing_address: None,
        }
    }

    /// Use another absolute Cloud API base URL.
    pub fn base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, VerificationError> {
        self.config.set_base_url(base_url)?;
        Ok(self)
    }

    /// Restrict the report to attestations using this signing algorithm.
    pub fn signing_algo(mut self, signing_algo: SigningAlgo) -> Self {
        self.signing_algo = Some(signing_algo);
        self
    }

    /// Restrict the report to attestations using this signing address.
    pub fn signing_address(mut self, signing_address: impl Into<String>) -> Self {
        self.signing_address = Some(signing_address.into());
        self
    }

    /// Fetch evidence with a fresh nonce. Cloud API currently returns exactly
    /// one candidate, and this helper enforces that contract.
    pub async fn send(self) -> Result<FetchedModelAttestations, SdkError> {
        fetch_model_attestations_with_config(
            &self.config,
            &self.model,
            self.signing_algo,
            self.signing_address.as_deref(),
        )
        .await
    }
}

/// Build a request for the model evidence associated with one `provider_tee`
/// signature.
pub struct ModelAttestationForSignatureRequest<'a> {
    request: ModelAttestationsRequest,
    signature: &'a CompletionSignatureReference,
}

impl<'a> ModelAttestationForSignatureRequest<'a> {
    pub fn new(
        api_key: impl Into<String>,
        model: impl Into<String>,
        signature: &'a CompletionSignatureReference,
    ) -> Self {
        let request = ModelAttestationsRequest::new(api_key, model)
            .signing_algo(signature.signer.signing_algo)
            .signing_address(&signature.signer.signing_address);
        Self { request, signature }
    }

    /// Use another absolute Cloud API base URL.
    pub fn base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, VerificationError> {
        self.request = self.request.base_url(base_url)?;
        Ok(self)
    }

    /// Fetch model evidence and select the candidate matching the signature
    /// signer.
    pub async fn send(self) -> Result<FetchedModelAttestation, SdkError> {
        require_provider_signature(self.signature)?;
        let fetched = self.request.send().await?;
        let attestation =
            find_model_attestation_for_signature(&fetched.attestations, self.signature)?.clone();
        Ok(FetchedModelAttestation {
            attestation,
            nonce: fetched.nonce,
        })
    }
}

/// Build a request for standalone Gateway evidence.
pub struct GatewayAttestationRequest {
    config: CloudApiRequestConfig,
    signing_algo: Option<SigningAlgo>,
}

impl GatewayAttestationRequest {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            config: CloudApiRequestConfig::new(api_key),
            signing_algo: None,
        }
    }

    /// Use another absolute Cloud API base URL.
    pub fn base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, VerificationError> {
        self.config.set_base_url(base_url)?;
        Ok(self)
    }

    /// Request evidence for this Gateway signing algorithm.
    pub fn signing_algo(mut self, signing_algo: SigningAlgo) -> Self {
        self.signing_algo = Some(signing_algo);
        self
    }

    /// Fetch Gateway evidence with a fresh nonce and the TLS peer observed by
    /// reqwest for this exact HTTPS request, when the runtime exposes it.
    pub async fn send(self) -> Result<FetchedGatewayAttestation, SdkError> {
        fetch_gateway_attestation_with_config(&self.config, self.signing_algo).await
    }
}

/// Build a request for a completion signature.
pub struct CompletionSignatureRequest {
    config: CloudApiRequestConfig,
    completion_id: String,
    signing_algo: Option<SigningAlgo>,
}

impl CompletionSignatureRequest {
    pub fn new(api_key: impl Into<String>, completion_id: impl Into<String>) -> Self {
        Self {
            config: CloudApiRequestConfig::new(api_key),
            completion_id: completion_id.into(),
            signing_algo: None,
        }
    }

    /// Use another absolute Cloud API base URL.
    pub fn base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, VerificationError> {
        self.config.set_base_url(base_url)?;
        Ok(self)
    }

    /// Request a completion signature using this signing algorithm.
    pub fn signing_algo(mut self, signing_algo: SigningAlgo) -> Self {
        self.signing_algo = Some(signing_algo);
        self
    }

    /// Send the request without treating a 2xx unavailable envelope as an
    /// error. A pending 404 remains a retryable HTTP error.
    pub async fn send(self) -> Result<CompletionSignatureLookup, SdkError> {
        lookup_completion_signature_with_config(
            &self.config,
            &self.completion_id,
            self.signing_algo,
        )
        .await
    }
}

/// Fetch NEAR model evidence using the production endpoint. Use
/// [`ModelAttestationsRequest`] to add request filters or select a different
/// base URL.
pub async fn fetch_model_attestations(
    api_key: &str,
    model: &str,
) -> Result<FetchedModelAttestations, SdkError> {
    ModelAttestationsRequest::new(api_key, model).send().await
}

/// Fetch model evidence for a `provider_tee` completion signature using the
/// production endpoint. Use [`ModelAttestationForSignatureRequest`] to select
/// a different base URL.
pub async fn fetch_model_attestation_for_signature(
    api_key: &str,
    model: &str,
    signature: &CompletionSignatureReference,
) -> Result<FetchedModelAttestation, SdkError> {
    ModelAttestationForSignatureRequest::new(api_key, model, signature)
        .send()
        .await
}

/// Fetch standalone Gateway evidence using the production endpoint. The
/// built-in reqwest client records the TLS peer certificate for the evidence
/// request when the runtime exposes it. Use [`GatewayAttestationRequest`] to
/// select another signing algorithm or endpoint.
pub async fn fetch_gateway_attestation(
    api_key: &str,
) -> Result<FetchedGatewayAttestation, SdkError> {
    GatewayAttestationRequest::new(api_key).send().await
}

/// Look up a completion signature using the production endpoint and built-in
/// reqwest transport. Use [`CompletionSignatureRequest`] to select a different
/// base URL or signing algorithm.
pub async fn lookup_completion_signature(
    api_key: &str,
    completion_id: &str,
) -> Result<CompletionSignatureLookup, SdkError> {
    CompletionSignatureRequest::new(api_key, completion_id)
        .send()
        .await
}

/// Fetch a completion signature using the production endpoint and built-in
/// reqwest transport. Use [`lookup_completion_signature`] when a 2xx
/// unavailable envelope is an ordinary application state.
pub async fn fetch_completion_signature(
    api_key: &str,
    completion_id: &str,
) -> Result<CompletionSignature, SdkError> {
    require_completion_signature(lookup_completion_signature(api_key, completion_id).await?)
        .map_err(Into::into)
}

fn require_completion_signature(
    lookup: CompletionSignatureLookup,
) -> Result<CompletionSignature, ApiError> {
    match lookup {
        CompletionSignatureLookup::Found(signature) => Ok(signature),
        CompletionSignatureLookup::Unavailable(unavailable) => {
            Err(ApiError::CompletionSignatureUnavailable {
                provider_error_code: unavailable.error_code,
            })
        }
    }
}

/// Select the exact model evidence matching a `provider_tee` signature. It
/// performs no quote or response-signature verification itself.
pub fn find_model_attestation_for_signature<'a>(
    attestations: &'a [ModelAttestation],
    signature: &CompletionSignatureReference,
) -> Result<&'a ModelAttestation, SdkError> {
    require_provider_signature(signature)?;
    let mut matches = Vec::new();
    for attestation in attestations {
        if signer_matches(&attestation.evidence.signer, &signature.signer) {
            matches.push(attestation);
        }
    }
    match matches.len() {
        0 => Err(ApiError::ModelAttestationSignerNotFound.into()),
        1 => Ok(matches[0]),
        matching_count => Err(ApiError::AmbiguousModelAttestationSigner {
            matching_count,
            total_count: attestations.len(),
        }
        .into()),
    }
}

async fn fetch_model_attestations_with_config(
    config: &CloudApiRequestConfig,
    model: &str,
    signing_algo: Option<SigningAlgo>,
    signing_address: Option<&str>,
) -> Result<FetchedModelAttestations, SdkError> {
    let nonce = generate_nonce();
    let mut url = config.endpoint("attestation/report")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("model", model);
        query.append_pair("provider", "near");
        query.append_pair("nonce", &nonce);
        query.append_pair("include_tls_fingerprint", "false");
        if let Some(signing_algo) = signing_algo {
            query.append_pair("signing_algo", &signing_algo.to_string());
        }
        if let Some(signing_address) = signing_address {
            query.append_pair("signing_address", signing_address);
        }
    }
    let cloud_response = get_cloud_api_response(
        config,
        url,
        ApiResource::ModelAttestation,
        Some((NO_ALIASING_HEADER, "true")),
    )
    .await?;
    let response: WireModelAttestationResponse = decode_wire_response(
        &cloud_response.body,
        ApiResource::ModelAttestation,
        "model_attestations",
    )?;
    if response.model_attestations.len() != 1 {
        return Err(ApiError::UnexpectedModelAttestationCount {
            actual_count: response.model_attestations.len(),
        }
        .into());
    }
    let attestations = response
        .model_attestations
        .into_iter()
        .enumerate()
        .map(|(index, attestation)| {
            map_model_attestation(attestation, &format!("model_attestations[{index}]"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for attestation in &attestations {
        require_matching_api_nonce(
            &attestation.evidence.nonce,
            &nonce,
            ApiResource::ModelAttestation,
        )?;
    }
    Ok(FetchedModelAttestations {
        attestations,
        nonce,
    })
}

async fn fetch_gateway_attestation_with_config(
    config: &CloudApiRequestConfig,
    signing_algo: Option<SigningAlgo>,
) -> Result<FetchedGatewayAttestation, SdkError> {
    let nonce = generate_nonce();
    let mut url = config.endpoint("attestation/report")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("nonce", &nonce);
        if let Some(signing_algo) = signing_algo {
            query.append_pair("signing_algo", &signing_algo.to_string());
        }
        query.append_pair("include_tls_fingerprint", "true");
    }
    let cloud_response =
        get_cloud_api_response(config, url, ApiResource::GatewayAttestation, None).await?;
    let response: WireGatewayAttestationResponse = decode_wire_response(
        &cloud_response.body,
        ApiResource::GatewayAttestation,
        "gateway_attestation",
    )?;
    let attestation = map_gateway_attestation(response.gateway_attestation, "gateway_attestation")?;
    require_matching_api_nonce(
        &attestation.evidence.nonce,
        &nonce,
        ApiResource::GatewayAttestation,
    )?;
    Ok(FetchedGatewayAttestation {
        attestation,
        client_binding: GatewayClientBinding {
            nonce,
            peer_spki_fingerprint: cloud_response.peer_spki_fingerprint,
        },
    })
}

async fn lookup_completion_signature_with_config(
    config: &CloudApiRequestConfig,
    completion_id: &str,
    signing_algo: Option<SigningAlgo>,
) -> Result<CompletionSignatureLookup, SdkError> {
    let mut url = config.endpoint("signature")?;
    url.path_segments_mut()
        .map_err(|_| VerificationError::InvalidInput {
            field: "base_url".to_owned(),
            reason: "cannot construct signature endpoint".to_owned(),
        })?
        .push(completion_id);
    if let Some(signing_algo) = signing_algo {
        url.query_pairs_mut()
            .append_pair("signing_algo", &signing_algo.to_string());
    }
    let cloud_response =
        get_cloud_api_response(config, url, ApiResource::CompletionSignature, None).await?;
    let response: WireCompletionSignatureResponse = decode_wire_response(
        &cloud_response.body,
        ApiResource::CompletionSignature,
        "signature",
    )?;
    map_completion_signature_lookup(response).map_err(Into::into)
}

async fn get_cloud_api_response(
    config: &CloudApiRequestConfig,
    url: Url,
    resource: ApiResource,
    extra_header: Option<(&str, &str)>,
) -> Result<CloudApiResponse, SdkError> {
    let headers = build_cloud_api_headers(config, extra_header)?;
    let client = if resource == ApiResource::GatewayAttestation {
        &config.gateway_client
    } else {
        &config.client
    };
    let response =
        client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(|_| ApiError::Transport {
                resource,
                reason: ApiTransportReason::Request,
            })?;
    let status = response.status().as_u16();
    let peer_spki_fingerprint = (resource == ApiResource::GatewayAttestation)
        .then(|| peer_spki_fingerprint(&response))
        .flatten();
    let body = response.text().await.map_err(|_| ApiError::Transport {
        resource,
        reason: ApiTransportReason::ResponseBody,
    })?;
    if !(200..300).contains(&status) {
        return Err(ApiError::HttpStatus { resource, status }.into());
    }
    Ok(CloudApiResponse {
        body,
        peer_spki_fingerprint,
    })
}

fn build_cloud_api_headers(
    config: &CloudApiRequestConfig,
    extra_header: Option<(&str, &str)>,
) -> Result<HeaderMap, VerificationError> {
    let mut headers = HeaderMap::new();
    let authorization =
        HeaderValue::from_str(&format!("Bearer {}", config.api_key)).map_err(|_| {
            VerificationError::InvalidInput {
                field: "api_key".to_owned(),
                reason: "expected an HTTP header value".to_owned(),
            }
        })?;
    headers.insert(AUTHORIZATION, authorization);
    if let Some((name, value)) = extra_header {
        let name = HeaderName::from_bytes(name.as_bytes())
            .expect("the SDK only supplies static valid header names");
        let value =
            HeaderValue::from_str(value).expect("the SDK only supplies static valid header values");
        headers.insert(name, value);
    }
    Ok(headers)
}

fn peer_spki_fingerprint(response: &reqwest::Response) -> Option<String> {
    let certificate = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()?
        .peer_certificate()?;
    let certificate = Certificate::from_der(certificate).ok()?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()?;
    Some(hex::encode(sha256(spki)))
}

struct CloudApiResponse {
    body: String,
    peer_spki_fingerprint: Option<String>,
}

fn parse_base_url(value: &str) -> Result<Url, VerificationError> {
    let mut url = Url::parse(value).map_err(|_| invalid_base_url())?;
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn invalid_base_url() -> VerificationError {
    VerificationError::InvalidInput {
        field: "base_url".to_owned(),
        reason: "expected an absolute URL".to_owned(),
    }
}

fn require_provider_signature(
    signature: &CompletionSignatureReference,
) -> Result<(), VerificationError> {
    if signature.kind != CompletionSignatureKind::ProviderTee {
        return Err(VerificationError::SignatureKindMismatch {
            expected: CompletionSignatureKind::ProviderTee,
            actual: signature.kind,
        });
    }
    Ok(())
}

fn signer_matches(left: &SigningIdentity, right: &SigningIdentity) -> bool {
    let (Ok(left_address), Ok(right_address)) = (
        decode_hex(&left.signing_address),
        decode_hex(&right.signing_address),
    ) else {
        return false;
    };
    left.signing_algo == right.signing_algo && left_address == right_address
}

fn require_matching_api_nonce(
    reported_nonce: &str,
    requested_nonce: &str,
    resource: ApiResource,
) -> Result<(), ApiError> {
    let matches = matches!(
        (
            decode_hex(reported_nonce),
            decode_hex(requested_nonce),
        ),
        (Ok(reported), Ok(requested)) if reported == requested
    );
    if matches {
        return Ok(());
    }
    Err(ApiError::NonceMismatch { resource })
}

/// Decode one complete endpoint response into its wire type. This is the only
/// JSON shape-decoding step between a Cloud API response body and its domain
/// mapping, and attaches a stable root path to shape errors.
fn decode_wire_response<T>(
    body: &str,
    resource: ApiResource,
    root_path: &str,
) -> Result<T, ApiError>
where
    T: for<'de> Deserialize<'de>,
{
    let mut deserializer = serde_json::Deserializer::from_str(body);
    let response = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        if error.inner().is_syntax() || error.inner().is_eof() {
            return ApiError::InvalidJson { resource };
        }
        ApiError::InvalidResponse {
            path: response_error_path(root_path, &error.path().to_string()),
            expected: "the documented Cloud API response shape".to_owned(),
        }
    })?;
    deserializer
        .end()
        .map_err(|_| ApiError::InvalidJson { resource })?;
    Ok(response)
}

fn response_error_path(root_path: &str, nested_path: &str) -> String {
    match nested_path {
        "" | "." => root_path.to_owned(),
        _ if root_path.is_empty() || nested_path == root_path => nested_path.to_owned(),
        _ if nested_path.starts_with(root_path)
            && matches!(
                nested_path.as_bytes().get(root_path.len()),
                Some(b'.' | b'[')
            ) =>
        {
            nested_path.to_owned()
        }
        _ if nested_path.starts_with('[') => format!("{root_path}{nested_path}"),
        _ => format!("{root_path}.{nested_path}"),
    }
}

fn map_model_attestation(
    value: WireModelAttestation,
    path: &str,
) -> Result<ModelAttestation, ApiError> {
    let (evidence, declared_spki_fingerprint, reported_quote_data) =
        map_evidence(value.attestation, path)?;
    Ok(ModelAttestation {
        evidence,
        declared_spki_fingerprint,
        reported_quote_data,
        nvidia_payload: value.nvidia_payload,
    })
}

fn map_gateway_attestation(
    value: WireAttestation,
    path: &str,
) -> Result<GatewayAttestation, ApiError> {
    let (evidence, declared_spki_fingerprint, reported_quote_data) = map_evidence(value, path)?;
    let declared_spki_fingerprint =
        declared_spki_fingerprint.ok_or_else(|| ApiError::InvalidResponse {
            path: format!("{path}.tls_cert_fingerprint"),
            expected: "a string".to_owned(),
        })?;
    let reported_quote_data = reported_quote_data.ok_or_else(|| ApiError::InvalidResponse {
        path: format!("{path}.report_data"),
        expected: "a string".to_owned(),
    })?;
    Ok(GatewayAttestation {
        evidence,
        declared_spki_fingerprint,
        reported_quote_data,
    })
}

fn map_evidence(
    value: WireAttestation,
    path: &str,
) -> Result<(AttestationEvidence, Option<String>, Option<String>), ApiError> {
    validate_api_nonce(&value.request_nonce, &format!("{path}.request_nonce"))?;
    validate_api_signing_identity(
        value.signing_algo,
        &value.signing_address,
        &format!("{path}.signing_address"),
    )?;
    Ok((
        AttestationEvidence {
            nonce: value.request_nonce,
            signer: SigningIdentity {
                signing_algo: value.signing_algo,
                signing_address: value.signing_address,
            },
            intel_quote: value.intel_quote,
            event_log: value.event_log,
            app_compose: value.info.tcb_info.app_compose,
        },
        value.tls_cert_fingerprint,
        value.report_data,
    ))
}

fn validate_api_nonce(value: &str, path: &str) -> Result<(), ApiError> {
    require_hex_length(value, 32).map_err(|_| ApiError::InvalidResponse {
        path: path.to_owned(),
        expected: "a 32-byte hexadecimal nonce".to_owned(),
    })?;
    Ok(())
}

fn validate_api_signing_identity(
    signing_algo: SigningAlgo,
    signing_address: &str,
    path: &str,
) -> Result<(), ApiError> {
    let expected = match signing_algo {
        SigningAlgo::Ecdsa => 20,
        SigningAlgo::Ed25519 => 32,
    };
    require_hex_length(signing_address, expected).map_err(|_| ApiError::InvalidResponse {
        path: path.to_owned(),
        expected: format!("a {expected}-byte hexadecimal signing address"),
    })?;
    Ok(())
}

fn map_completion_signature_lookup(
    value: WireCompletionSignatureResponse,
) -> Result<CompletionSignatureLookup, ApiError> {
    if let Some(unavailable) = value.unavailable() {
        return Ok(CompletionSignatureLookup::Unavailable(unavailable));
    }
    let signature = value.require_signature()?;
    validate_api_signing_identity(
        signature.signing_algo,
        &signature.signing_address,
        "signature.signing_address",
    )?;
    Ok(CompletionSignatureLookup::Found(CompletionSignature {
        kind: signature.signature_kind,
        signed_text: signature.text,
        signature: signature.signature,
        signer: SigningIdentity {
            signing_algo: signature.signing_algo,
            signing_address: signature.signing_address,
        },
    }))
}

#[derive(Deserialize)]
struct WireModelAttestationResponse {
    model_attestations: Vec<WireModelAttestation>,
}

#[derive(Deserialize)]
struct WireGatewayAttestationResponse {
    gateway_attestation: WireAttestation,
}

#[derive(Deserialize)]
struct WireModelAttestation {
    #[serde(flatten)]
    attestation: WireAttestation,
    nvidia_payload: Option<String>,
}

#[derive(Deserialize)]
struct WireAttestation {
    request_nonce: String,
    signing_algo: SigningAlgo,
    signing_address: String,
    intel_quote: String,
    event_log: AttestationEventLog,
    tls_cert_fingerprint: Option<String>,
    report_data: Option<String>,
    info: WireInfo,
}

#[derive(Deserialize)]
struct WireInfo {
    tcb_info: WireTcbInfo,
}

struct WireTcbInfo {
    app_compose: String,
}

#[derive(Deserialize)]
struct WireTcbInfoObject {
    app_compose: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WireTcbInfoSource {
    Object(WireTcbInfoObject),
    Json(String),
}

impl<'de> Deserialize<'de> for WireTcbInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let source = WireTcbInfoSource::deserialize(deserializer)?;
        let value = match source {
            WireTcbInfoSource::Object(value) => value,
            WireTcbInfoSource::Json(value) => {
                serde_json::from_str(&value).map_err(D::Error::custom)?
            }
        };
        Ok(Self {
            app_compose: value.app_compose,
        })
    }
}

#[derive(Deserialize)]
struct WireCompletionSignatureResponse {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    signing_address: Option<String>,
    #[serde(default)]
    signing_algo: Option<SigningAlgo>,
    #[serde(default)]
    signature_kind: Option<CompletionSignatureKind>,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

impl WireCompletionSignatureResponse {
    fn unavailable(&self) -> Option<SignatureUnavailable> {
        let (Some(error_code), Some(message)) = (&self.error_code, &self.message) else {
            return None;
        };
        if self.text.is_none()
            && self.signature.is_none()
            && self.signing_address.is_none()
            && self.signing_algo.is_none()
            && self.signature_kind.is_none()
        {
            return Some(SignatureUnavailable {
                error_code: error_code.clone(),
                message: message.clone(),
            });
        }
        None
    }

    fn require_signature(self) -> Result<WireCompletionSignature, ApiError> {
        Ok(WireCompletionSignature {
            text: require_completion_signature_field(self.text, "text")?,
            signature: require_completion_signature_field(self.signature, "signature")?,
            signing_address: require_completion_signature_field(
                self.signing_address,
                "signing_address",
            )?,
            signing_algo: require_completion_signature_field(self.signing_algo, "signing_algo")?,
            signature_kind: require_completion_signature_field(
                self.signature_kind,
                "signature_kind",
            )?,
        })
    }
}

struct WireCompletionSignature {
    text: String,
    signature: String,
    signing_address: String,
    signing_algo: SigningAlgo,
    signature_kind: CompletionSignatureKind,
}

fn require_completion_signature_field<T>(value: Option<T>, field: &str) -> Result<T, ApiError> {
    value.ok_or_else(|| ApiError::InvalidResponse {
        path: format!("signature.{field}"),
        expected: "the documented Cloud API response shape".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_base_url_preserves_the_v1_path_when_resolving_an_endpoint() {
        let config = CloudApiRequestConfig::new("test-key");

        assert_eq!(
            config.endpoint("attestation/report").unwrap().as_str(),
            "https://cloud-api.near.ai/v1/attestation/report",
        );
    }

    fn decode_test_wire<T>(
        value: serde_json::Value,
        resource: ApiResource,
        root_path: &str,
    ) -> Result<T, ApiError>
    where
        T: serde::de::DeserializeOwned,
    {
        decode_wire_response(&value.to_string(), resource, root_path)
    }

    #[test]
    fn normalizes_optional_model_wire_fields_to_none() {
        for value in [
            json!({
                "request_nonce": "11".repeat(32),
                "signing_algo": "ecdsa",
                "signing_address": "22".repeat(20),
                "intel_quote": "aa",
                "event_log": [],
                "info": {"tcb_info": {"app_compose": "{}"}},
            }),
            json!({
                "request_nonce": "11".repeat(32),
                "signing_algo": "ecdsa",
                "signing_address": "22".repeat(20),
                "intel_quote": "aa",
                "event_log": [],
                "tls_cert_fingerprint": null,
                "report_data": null,
                "nvidia_payload": null,
                "info": {"tcb_info": {"app_compose": "{}"}},
            }),
        ] {
            let response: WireModelAttestationResponse = decode_test_wire(
                json!({"model_attestations": [value]}),
                ApiResource::ModelAttestation,
                "model_attestations",
            )
            .unwrap();
            let attestation = map_model_attestation(
                response
                    .model_attestations
                    .into_iter()
                    .next()
                    .expect("one model attestation"),
                "model_attestations[0]",
            )
            .unwrap();
            assert_eq!(attestation.declared_spki_fingerprint, None);
            assert_eq!(attestation.reported_quote_data, None);
            assert_eq!(attestation.nvidia_payload, None);
        }
    }

    #[test]
    fn gateway_response_requires_report_data() {
        let response: WireGatewayAttestationResponse = decode_test_wire(
            json!({
                "gateway_attestation": {
                    "request_nonce": "11".repeat(32),
                    "signing_algo": "ecdsa",
                    "signing_address": "22".repeat(20),
                    "intel_quote": "aa",
                    "event_log": [],
                    "tls_cert_fingerprint": "33".repeat(32),
                    "info": {"tcb_info": {"app_compose": "{}"}},
                },
            }),
            ApiResource::GatewayAttestation,
            "gateway_attestation",
        )
        .unwrap();
        let error = map_gateway_attestation(response.gateway_attestation, "gateway_attestation")
            .unwrap_err();

        assert!(matches!(
            error,
            ApiError::InvalidResponse { ref path, .. }
                if path == "gateway_attestation.report_data"
        ));
    }

    #[test]
    fn gateway_response_requires_a_tls_fingerprint() {
        let response: WireGatewayAttestationResponse = decode_test_wire(
            json!({
                "gateway_attestation": {
                    "request_nonce": "11".repeat(32),
                    "signing_algo": "ecdsa",
                    "signing_address": "22".repeat(20),
                    "intel_quote": "aa",
                    "event_log": [],
                    "report_data": "00".repeat(64),
                    "info": {"tcb_info": {"app_compose": "{}"}},
                },
            }),
            ApiResource::GatewayAttestation,
            "gateway_attestation",
        )
        .unwrap();
        let error = map_gateway_attestation(response.gateway_attestation, "gateway_attestation")
            .unwrap_err();

        assert!(matches!(
            error,
            ApiError::InvalidResponse { ref path, .. }
                if path == "gateway_attestation.tls_cert_fingerprint"
        ));
    }

    #[test]
    fn wire_decoder_keeps_malformed_json_as_an_api_json_error() {
        let result = decode_wire_response::<WireModelAttestationResponse>(
            "{",
            ApiResource::ModelAttestation,
            "model_attestations",
        );

        assert!(matches!(
            result,
            Err(ApiError::InvalidJson {
                resource: ApiResource::ModelAttestation
            })
        ));
    }

    #[test]
    fn typed_model_records_preserve_wire_nonce_and_signer_validation() {
        for (request_nonce, signing_address, expected_path) in [
            ("aa".to_owned(), "22".repeat(20), "request_nonce"),
            ("11".repeat(32), "aa".to_owned(), "signing_address"),
        ] {
            let response: WireModelAttestationResponse = decode_test_wire(
                json!({
                    "model_attestations": [{
                        "request_nonce": request_nonce,
                        "signing_algo": "ecdsa",
                        "signing_address": signing_address,
                        "intel_quote": "aa",
                        "event_log": [],
                        "info": {"tcb_info": {"app_compose": "{}"}},
                    }],
                }),
                ApiResource::ModelAttestation,
                "model_attestations",
            )
            .unwrap();

            let error = map_model_attestation(
                response
                    .model_attestations
                    .into_iter()
                    .next()
                    .expect("one model attestation"),
                "model_attestations[0]",
            )
            .unwrap_err();
            assert!(matches!(
                error,
                ApiError::InvalidResponse { ref path, .. }
                    if path == &format!("model_attestations[0].{expected_path}")
            ));
        }
    }

    #[test]
    fn typed_model_records_accept_json_string_tcb_info() {
        let response: WireModelAttestationResponse = decode_test_wire(
            json!({
                "model_attestations": [{
                    "request_nonce": "11".repeat(32),
                    "signing_algo": "ecdsa",
                    "signing_address": "22".repeat(20),
                    "intel_quote": "aa",
                    "event_log": [],
                    "info": {"tcb_info": "{\"app_compose\":\"{}\"}"},
                }],
            }),
            ApiResource::ModelAttestation,
            "model_attestations",
        )
        .unwrap();
        let attestation = map_model_attestation(
            response
                .model_attestations
                .into_iter()
                .next()
                .expect("one model attestation"),
            "model_attestations[0]",
        )
        .unwrap();

        assert_eq!(attestation.evidence.app_compose, "{}");
    }

    #[test]
    fn accepts_an_equivalent_nonce_encoding() {
        require_matching_api_nonce(
            &format!("0X{}", "AB".repeat(32)),
            &"ab".repeat(32),
            ApiResource::ModelAttestation,
        )
        .unwrap();
    }

    #[test]
    fn typed_model_records_reject_invalid_json_string_tcb_info() {
        let result = decode_test_wire::<WireModelAttestationResponse>(
            json!({
                "model_attestations": [{
                    "request_nonce": "11".repeat(32),
                    "signing_algo": "ecdsa",
                    "signing_address": "22".repeat(20),
                    "intel_quote": "aa",
                    "event_log": [],
                    "info": {"tcb_info": "not JSON"},
                }],
            }),
            ApiResource::ModelAttestation,
            "model_attestations",
        );

        assert!(matches!(
            result,
            Err(ApiError::InvalidResponse { ref path, .. })
                if path.starts_with("model_attestations[0]")
        ));
    }

    #[test]
    fn rejects_missing_or_unknown_completion_signature_kind() {
        for response in [
            json!({
                "text": "signed",
                "signature": "aa",
                "signing_address": "22".repeat(20),
                "signing_algo": "ecdsa",
            }),
            json!({
                "text": "signed",
                "signature": "aa",
                "signing_address": "22".repeat(20),
                "signing_algo": "ecdsa",
                "signature_kind": "unknown",
            }),
        ] {
            let error = decode_test_wire::<WireCompletionSignatureResponse>(
                response,
                ApiResource::CompletionSignature,
                "signature",
            )
            .and_then(map_completion_signature_lookup)
            .unwrap_err();
            assert!(matches!(error, ApiError::InvalidResponse { .. }));
        }
    }

    #[test]
    fn signature_fields_prevent_an_error_envelope_from_being_treated_as_unavailable() {
        let response: WireCompletionSignatureResponse = decode_test_wire(
            json!({
                "error_code": "pending",
                "message": "not ready",
                "text": "partial signature",
            }),
            ApiResource::CompletionSignature,
            "signature",
        )
        .unwrap();

        let error = map_completion_signature_lookup(response).unwrap_err();
        assert!(matches!(error, ApiError::InvalidResponse { .. }));
    }

    #[test]
    fn strict_signature_fetch_maps_an_unavailable_lookup_to_an_api_error() {
        let error = require_completion_signature(CompletionSignatureLookup::Unavailable(
            SignatureUnavailable {
                error_code: "pending".to_owned(),
                message: "not ready".to_owned(),
            },
        ))
        .unwrap_err();

        assert!(matches!(
            error,
            ApiError::CompletionSignatureUnavailable { ref provider_error_code }
                if provider_error_code == "pending"
        ));
        assert_eq!(error.code(), "api.completion_signature_unavailable");
        assert!(!error.retryable());
    }
}
