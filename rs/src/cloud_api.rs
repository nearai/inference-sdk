use crate::errors::{ApiError, ApiResource, ApiTransportReason, SdkError, VerificationError};
use crate::types::{
    AttestationEventLog, AttestationEvidence, CompletionSignature, CompletionSignatureKind,
    CompletionSignatureLookup, CompletionSignatureReference, FetchCompletionSignatureInput,
    FetchGatewayAttestationInput, FetchModelAttestationForSignatureInput,
    FetchModelAttestationsInput, FetchedGatewayAttestation, FetchedModelAttestation,
    FetchedModelAttestations, FindModelAttestationForSignatureInput, GatewayAttestation,
    ModelAttestation, SignatureUnavailable, SigningAlgo, SigningIdentity,
};
use crate::util::{generate_nonce, normalize_hex, require_hex_length};
use async_trait::async_trait;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION},
    Client, Url,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

/// Default production endpoint used when a helper does not select another one.
pub const DEFAULT_NEAR_AI_CLOUD_BASE_URL: &str = "https://cloud-api.near.ai/v1";

/// Set this on model-attestation requests to reject aliases before dispatch.
pub const NO_ALIASING_HEADER: &str = "x-no-aliasing";

/// A Cloud API request supplied to a caller-owned transport.
///
/// `headers` includes the authorization header required by the SDK. A custom
/// transport must send this exact request and must not reuse a peer TLS
/// fingerprint from a different connection.
pub struct NearAiCloudRequest {
    pub url: Url,
    pub headers: HeaderMap,
}

/// A Cloud API response returned by a caller-owned transport.
///
/// A TLS-aware transport can set `peer_spki_fingerprint` to the SHA-256 SPKI
/// fingerprint observed for this exact HTTPS request. The built-in reqwest
/// transport leaves it as `None` because it does not expose peer certificate
/// data through this SDK's request helper.
pub struct NearAiCloudResponse {
    pub status: u16,
    pub body: String,
    pub peer_spki_fingerprint: Option<String>,
}

/// Transport used by the Cloud API helpers.
///
/// Implement this when an application needs TLS metadata for a Gateway
/// attestation request. Return a descriptive error string for a request or
/// request or response-body failure; the SDK maps it to a structured
/// `ApiError` without exposing transport-provided text.
#[async_trait]
pub trait NearAiCloudTransport: Send + Sync {
    async fn get(
        &self,
        request: NearAiCloudRequest,
    ) -> Result<NearAiCloudResponse, ApiTransportReason>;
}

#[derive(Clone)]
struct ReqwestNearAiCloudTransport {
    client: Client,
}

#[async_trait]
impl NearAiCloudTransport for ReqwestNearAiCloudTransport {
    async fn get(
        &self,
        request: NearAiCloudRequest,
    ) -> Result<NearAiCloudResponse, ApiTransportReason> {
        let response = self
            .client
            .get(request.url)
            .headers(request.headers)
            .send()
            .await
            .map_err(|_| ApiTransportReason::Request)?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .map_err(|_| ApiTransportReason::ResponseBody)?;
        Ok(NearAiCloudResponse {
            status,
            body,
            peer_spki_fingerprint: None,
        })
    }
}

/// Shared Cloud API transport configuration.
#[derive(Clone)]
pub struct NearAiCloudOptions {
    api_key: String,
    base_url: Url,
    transport: Arc<dyn NearAiCloudTransport>,
}

impl NearAiCloudOptions {
    pub fn new(api_key: impl Into<String>) -> Result<Self, VerificationError> {
        Self::with_base_url(api_key, DEFAULT_NEAR_AI_CLOUD_BASE_URL)
    }

    pub fn with_base_url(
        api_key: impl Into<String>,
        base_url: impl AsRef<str>,
    ) -> Result<Self, VerificationError> {
        Self::with_client(api_key, base_url, Client::new())
    }

    pub fn with_client(
        api_key: impl Into<String>,
        base_url: impl AsRef<str>,
        client: Client,
    ) -> Result<Self, VerificationError> {
        Self::with_transport(api_key, base_url, ReqwestNearAiCloudTransport { client })
    }

    /// Configure the Cloud API helpers with an application-owned transport.
    ///
    /// Use this for Gateway attestation when the application needs the TLS
    /// peer fingerprint associated with the exact evidence request. The
    /// transport's optional response fingerprint is returned by
    /// [`fetch_gateway_attestation`].
    pub fn with_transport(
        api_key: impl Into<String>,
        base_url: impl AsRef<str>,
        transport: impl NearAiCloudTransport + 'static,
    ) -> Result<Self, VerificationError> {
        let api_key = api_key.into();
        if api_key.is_empty()
            || api_key.chars().any(|value| value.is_control())
            || HeaderValue::from_str(&format!("Bearer {api_key}")).is_err()
        {
            return Err(VerificationError::InvalidInput {
                field: "api_key".to_owned(),
                reason: "expected a non-empty HTTP header value".to_owned(),
            });
        }
        let base_url = validate_base_url(base_url.as_ref())?;
        Ok(Self {
            api_key,
            base_url,
            transport: Arc::new(transport),
        })
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
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

/// Fetch NEAR model evidence with a fresh client nonce. The Cloud API
/// currently returns exactly one candidate and the helper enforces that
/// contract.
pub async fn fetch_model_attestations(
    cloud: &NearAiCloudOptions,
    input: FetchModelAttestationsInput<'_>,
) -> Result<FetchedModelAttestations, SdkError> {
    validate_model_query(&input)?;
    let nonce = generate_nonce();
    let mut url = cloud.endpoint("attestation/report")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("model", input.model);
        query.append_pair("provider", "near");
        query.append_pair("nonce", &nonce);
        if let Some(signing_algo) = input.signing_algo {
            query.append_pair("signing_algo", &signing_algo.to_string());
        }
        if let Some(signing_address) = input.signing_address {
            query.append_pair("signing_address", signing_address);
        }
    }
    let response = get_cloud_api_json(
        cloud,
        url,
        ApiResource::ModelAttestation,
        Some((NO_ALIASING_HEADER, "true")),
    )
    .await?;
    let response: WireModelAttestationResponse =
        deserialize_response(response.json, "model_attestations")?;
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
        .map(|(index, value)| {
            parse_model_attestation(value, &format!("model_attestations[{index}]"))
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

/// Fetch model evidence for a `provider_tee` completion signature, then select
/// the single candidate whose signer matches the signature signer.
pub async fn fetch_model_attestation_for_signature(
    cloud: &NearAiCloudOptions,
    input: FetchModelAttestationForSignatureInput<'_>,
) -> Result<FetchedModelAttestation, SdkError> {
    require_provider_signature(input.signature)?;
    let fetched = fetch_model_attestations(
        cloud,
        FetchModelAttestationsInput {
            model: input.model,
            signing_algo: Some(input.signature.signer.signing_algo),
            signing_address: Some(&input.signature.signer.signing_address),
        },
    )
    .await?;
    let attestation =
        find_model_attestation_for_signature(FindModelAttestationForSignatureInput {
            attestations: &fetched.attestations,
            signature: input.signature,
        })?
        .clone();
    Ok(FetchedModelAttestation {
        attestation,
        nonce: fetched.nonce,
    })
}

/// Fetch standalone Gateway evidence. The caller must independently observe
/// the TLS peer SPKI fingerprint for the attestation request.
pub async fn fetch_gateway_attestation(
    cloud: &NearAiCloudOptions,
    input: FetchGatewayAttestationInput,
) -> Result<FetchedGatewayAttestation, SdkError> {
    let nonce = generate_nonce();
    let mut url = cloud.endpoint("attestation/report")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("nonce", &nonce);
        query.append_pair(
            "signing_algo",
            &input
                .signing_algo
                .unwrap_or(SigningAlgo::Ed25519)
                .to_string(),
        );
        query.append_pair("include_tls_fingerprint", "true");
    }
    let cloud_response =
        get_cloud_api_json(cloud, url, ApiResource::GatewayAttestation, None).await?;
    let response: WireGatewayAttestationResponse =
        deserialize_response(cloud_response.json, "gateway_attestation")?;
    let attestation =
        parse_gateway_attestation(response.gateway_attestation, "gateway_attestation")?;
    require_matching_api_nonce(
        &attestation.evidence.nonce,
        &nonce,
        ApiResource::GatewayAttestation,
    )?;
    Ok(FetchedGatewayAttestation {
        attestation,
        nonce,
        peer_spki_fingerprint: validate_transport_peer_spki_fingerprint(
            cloud_response.peer_spki_fingerprint,
        )?,
    })
}

/// Look up a completion signature without treating a 200 unavailable envelope
/// as an error. A pending 404 remains a retryable `ApiError::HttpStatus`.
pub async fn lookup_completion_signature(
    cloud: &NearAiCloudOptions,
    input: FetchCompletionSignatureInput<'_>,
) -> Result<CompletionSignatureLookup, SdkError> {
    if input.completion_id.is_empty() {
        return Err(VerificationError::InvalidInput {
            field: "completion_id".to_owned(),
            reason: "expected a non-empty string".to_owned(),
        }
        .into());
    }
    let mut url = cloud.endpoint("signature")?;
    url.path_segments_mut()
        .map_err(|_| VerificationError::InvalidInput {
            field: "base_url".to_owned(),
            reason: "cannot construct signature endpoint".to_owned(),
        })?
        .push(input.completion_id);
    if let Some(signing_algo) = input.signing_algo {
        url.query_pairs_mut()
            .append_pair("signing_algo", &signing_algo.to_string());
    }
    let response = get_cloud_api_json(cloud, url, ApiResource::CompletionSignature, None).await?;
    Ok(parse_completion_signature_lookup(response.json)?)
}

/// Fetch a completion signature or return a local `signature.unavailable`
/// verification error for a 200 unavailable envelope.
pub async fn fetch_completion_signature(
    cloud: &NearAiCloudOptions,
    input: FetchCompletionSignatureInput<'_>,
) -> Result<CompletionSignature, SdkError> {
    match lookup_completion_signature(cloud, input).await? {
        CompletionSignatureLookup::Found(signature) => Ok(signature),
        CompletionSignatureLookup::Unavailable(unavailable) => {
            Err(VerificationError::SignatureUnavailable {
                provider_error_code: unavailable.error_code,
            }
            .into())
        }
    }
}

/// Select the exact model evidence matching a `provider_tee` signature. It
/// performs no quote or response-signature verification itself.
pub fn find_model_attestation_for_signature<'a>(
    input: FindModelAttestationForSignatureInput<'a>,
) -> Result<&'a ModelAttestation, SdkError> {
    require_provider_signature(input.signature)?;
    let mut matches = Vec::new();
    for (index, attestation) in input.attestations.iter().enumerate() {
        validate_public_signing_identity(
            &attestation.evidence.signer,
            &format!("attestations[{index}].signer"),
        )?;
        if signer_matches(&attestation.evidence.signer, &input.signature.signer) {
            matches.push(attestation);
        }
    }
    match matches.len() {
        0 => Err(ApiError::AttestationSignerMismatch.into()),
        1 => Ok(matches[0]),
        matching_count => Err(ApiError::AmbiguousModelAttestationSigner {
            matching_count,
            total_count: input.attestations.len(),
        }
        .into()),
    }
}

async fn get_cloud_api_json(
    cloud: &NearAiCloudOptions,
    url: Url,
    resource: ApiResource,
    extra_header: Option<(&str, &str)>,
) -> Result<CloudApiJsonResponse, ApiError> {
    let mut headers = HeaderMap::new();
    let authorization = HeaderValue::from_str(&format!("Bearer {}", cloud.api_key))
        .expect("NearAiCloudOptions validates API keys as HTTP header values");
    headers.insert(AUTHORIZATION, authorization);
    if let Some((name, value)) = extra_header {
        let name = HeaderName::from_bytes(name.as_bytes())
            .expect("the SDK only supplies static valid header names");
        let value =
            HeaderValue::from_str(value).expect("the SDK only supplies static valid header values");
        headers.insert(name, value);
    }
    let response = cloud
        .transport
        .get(NearAiCloudRequest { url, headers })
        .await
        .map_err(|reason| ApiError::Transport { resource, reason })?;
    if !(200..300).contains(&response.status) {
        return Err(ApiError::HttpStatus {
            resource,
            status: response.status,
        });
    }
    let json =
        serde_json::from_str(&response.body).map_err(|_| ApiError::InvalidJson { resource })?;
    Ok(CloudApiJsonResponse {
        json,
        peer_spki_fingerprint: response.peer_spki_fingerprint,
    })
}

struct CloudApiJsonResponse {
    json: Value,
    peer_spki_fingerprint: Option<String>,
}

fn validate_transport_peer_spki_fingerprint(
    fingerprint: Option<String>,
) -> Result<Option<String>, ApiError> {
    fingerprint
        .map(|fingerprint| {
            require_hex_length(&fingerprint, 32).map_err(|_| ApiError::InvalidResponse {
                path: "gateway_transport.peer_spki_fingerprint".to_owned(),
                expected: "a 32-byte hexadecimal SPKI fingerprint".to_owned(),
            })?;
            normalize_hex(&fingerprint).map_err(|_| ApiError::InvalidResponse {
                path: "gateway_transport.peer_spki_fingerprint".to_owned(),
                expected: "a 32-byte hexadecimal SPKI fingerprint".to_owned(),
            })
        })
        .transpose()
}

fn validate_base_url(value: &str) -> Result<Url, VerificationError> {
    if value.contains('?') || value.contains('#') {
        return Err(invalid_base_url());
    }
    let mut url = Url::parse(value).map_err(|_| invalid_base_url())?;
    if url.scheme() != "https"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid_base_url());
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn invalid_base_url() -> VerificationError {
    VerificationError::InvalidInput {
        field: "base_url".to_owned(),
        reason: "expected an absolute HTTPS URL without credentials, query, or fragment".to_owned(),
    }
}

fn validate_model_query(input: &FetchModelAttestationsInput<'_>) -> Result<(), VerificationError> {
    if input.model.is_empty() {
        return Err(VerificationError::InvalidInput {
            field: "model".to_owned(),
            reason: "expected a non-empty string".to_owned(),
        });
    }
    if let Some(signing_address) = input.signing_address {
        let bytes = require_hex_length_any(signing_address).map_err(|_| {
            VerificationError::InvalidInput {
                field: "signing_address".to_owned(),
                reason: "expected a hexadecimal signing address".to_owned(),
            }
        })?;
        let valid = match input.signing_algo {
            Some(SigningAlgo::Ecdsa) => bytes.len() == 20,
            Some(SigningAlgo::Ed25519) => bytes.len() == 32,
            None => bytes.len() == 20 || bytes.len() == 32,
        };
        if !valid {
            return Err(VerificationError::InvalidInput {
                field: "signing_address".to_owned(),
                reason: "address length does not match signing algorithm".to_owned(),
            });
        }
    }
    Ok(())
}

fn require_hex_length_any(value: &str) -> Result<Vec<u8>, ()> {
    crate::util::decode_hex(value)
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
    validate_public_signing_identity(&signature.signer, "signature.signer")?;
    Ok(())
}

fn validate_public_signing_identity(
    signer: &SigningIdentity,
    field: &str,
) -> Result<(), VerificationError> {
    let expected_length = match signer.signing_algo {
        SigningAlgo::Ecdsa => 20,
        SigningAlgo::Ed25519 => 32,
    };
    require_hex_length(&signer.signing_address, expected_length).map_err(|_| {
        VerificationError::InvalidInput {
            field: format!("{field}.signing_address"),
            reason: format!("expected a {expected_length}-byte hexadecimal signing address"),
        }
    })?;
    Ok(())
}

fn signer_matches(left: &SigningIdentity, right: &SigningIdentity) -> bool {
    let (Ok(left_address), Ok(right_address)) = (
        normalize_hex(&left.signing_address),
        normalize_hex(&right.signing_address),
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
    if normalize_hex(reported_nonce).ok().as_deref() == Some(requested_nonce) {
        return Ok(());
    }
    Err(ApiError::NonceMismatch { resource })
}

fn deserialize_response<T: for<'de> Deserialize<'de>>(
    value: Value,
    path: &str,
) -> Result<T, ApiError> {
    serde_path_to_error::deserialize(value).map_err(|error| {
        let nested_path = error.path().to_string();
        let path = if nested_path.is_empty() || nested_path == "." || nested_path == path {
            path.to_owned()
        } else {
            format!("{path}.{nested_path}")
        };
        ApiError::InvalidResponse {
            path,
            expected: "the documented Cloud API response shape".to_owned(),
        }
    })
}

fn parse_model_attestation(value: Value, path: &str) -> Result<ModelAttestation, ApiError> {
    validate_reported_quote_data_field(&value, path, false)?;
    let value: WireModelAttestation = deserialize_response(value, path)?;
    Ok(ModelAttestation {
        evidence: parse_evidence(value.attestation, path)?,
        nvidia_payload: value.nvidia_payload,
    })
}

fn parse_gateway_attestation(value: Value, path: &str) -> Result<GatewayAttestation, ApiError> {
    validate_reported_quote_data_field(&value, path, true)?;
    let value: WireAttestation = deserialize_response(value, path)?;
    let evidence = parse_evidence(value, path)?;
    let reported_quote_data =
        evidence
            .reported_quote_data
            .clone()
            .ok_or_else(|| ApiError::InvalidResponse {
                path: format!("{path}.report_data"),
                expected: "a string".to_owned(),
            })?;
    Ok(GatewayAttestation {
        evidence,
        reported_quote_data,
    })
}

fn parse_evidence(value: WireAttestation, path: &str) -> Result<AttestationEvidence, ApiError> {
    validate_api_nonce(&value.request_nonce, &format!("{path}.request_nonce"))?;
    validate_api_signing_identity(
        value.signing_algo,
        &value.signing_address,
        &format!("{path}.signing_address"),
    )?;
    let app_compose = parse_app_compose(value.info.tcb_info, &format!("{path}.info.tcb_info"))?;
    Ok(AttestationEvidence {
        nonce: value.request_nonce,
        signer: SigningIdentity {
            signing_algo: value.signing_algo,
            signing_address: value.signing_address,
        },
        intel_quote: value.intel_quote,
        event_log: value.event_log,
        app_compose,
        declared_spki_fingerprint: value.tls_cert_fingerprint,
        reported_quote_data: value.report_data,
    })
}

fn validate_reported_quote_data_field(
    value: &Value,
    path: &str,
    required: bool,
) -> Result<(), ApiError> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    match object.get("report_data") {
        Some(Value::String(_)) => Ok(()),
        None if !required => Ok(()),
        _ => Err(ApiError::InvalidResponse {
            path: format!("{path}.report_data"),
            expected: "a string".to_owned(),
        }),
    }
}

fn parse_app_compose(value: Value, path: &str) -> Result<String, ApiError> {
    let value = match value {
        Value::String(value) => {
            serde_json::from_str(&value).map_err(|_| ApiError::InvalidResponse {
                path: path.to_owned(),
                expected: "a JSON object with app_compose".to_owned(),
            })?
        }
        value => value,
    };
    value
        .as_object()
        .and_then(|value| value.get("app_compose"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ApiError::InvalidResponse {
            path: path.to_owned(),
            expected: "an object with string app_compose".to_owned(),
        })
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

fn parse_completion_signature_lookup(value: Value) -> Result<CompletionSignatureLookup, ApiError> {
    if let Some(object) = value.as_object() {
        let is_unavailable = object.get("error_code").and_then(Value::as_str).is_some()
            && object.get("message").and_then(Value::as_str).is_some()
            && [
                "text",
                "signature",
                "signing_address",
                "signing_algo",
                "signature_kind",
            ]
            .iter()
            .all(|field| !object.contains_key(*field));
        if is_unavailable {
            return Ok(CompletionSignatureLookup::Unavailable(
                SignatureUnavailable {
                    error_code: object["error_code"].as_str().unwrap().to_owned(),
                    message: object["message"].as_str().unwrap().to_owned(),
                },
            ));
        }
    }
    let signature: WireCompletionSignature = deserialize_response(value, "signature")?;
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
    model_attestations: Vec<Value>,
}

#[derive(Deserialize)]
struct WireGatewayAttestationResponse {
    gateway_attestation: Value,
}

#[derive(Deserialize)]
struct WireModelAttestation {
    #[serde(flatten)]
    attestation: WireAttestation,
    #[serde(default)]
    nvidia_payload: Option<String>,
}

#[derive(Deserialize)]
struct WireAttestation {
    request_nonce: String,
    signing_algo: SigningAlgo,
    signing_address: String,
    intel_quote: String,
    event_log: AttestationEventLog,
    #[serde(default)]
    tls_cert_fingerprint: Option<String>,
    #[serde(default)]
    report_data: Option<String>,
    info: WireInfo,
}

#[derive(Deserialize)]
struct WireInfo {
    tcb_info: Value,
}

#[derive(Deserialize)]
struct WireCompletionSignature {
    text: String,
    signature: String,
    signing_address: String,
    signing_algo: SigningAlgo,
    signature_kind: CompletionSignatureKind,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde_json::json;
    use wiremock::{
        matchers::{header, method, path, query_param},
        Mock, MockServer, Request, Respond, ResponseTemplate,
    };

    #[derive(Clone)]
    struct ModelAttestationResponder;

    impl Respond for ModelAttestationResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let nonce = request
                .url
                .query_pairs()
                .find(|(key, _)| key == "nonce")
                .map(|(_, value)| value.into_owned())
                .expect("request contains a nonce");
            ResponseTemplate::new(200).set_body_json(json!({
                "model_attestations": [{
                    "request_nonce": nonce,
                    "signing_algo": "ecdsa",
                    "signing_address": "22".repeat(20),
                    "intel_quote": "aa",
                    "event_log": [],
                    "info": {"tcb_info": {"app_compose": "{}"}},
                    "nvidia_payload": null,
                }]
            }))
        }
    }

    #[derive(Clone)]
    struct GatewayAttestationResponder;

    impl Respond for GatewayAttestationResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let nonce = request
                .url
                .query_pairs()
                .find(|(key, _)| key == "nonce")
                .map(|(_, value)| value.into_owned())
                .expect("request contains a nonce");
            ResponseTemplate::new(200).set_body_json(json!({
                "gateway_attestation": {
                    "request_nonce": nonce,
                    "signing_algo": "ed25519",
                    "signing_address": "22".repeat(32),
                    "intel_quote": "aa",
                    "event_log": [],
                    "tls_cert_fingerprint": "33".repeat(32),
                    "report_data": "00".repeat(64),
                    "info": {"tcb_info": {"app_compose": "{}"}},
                }
            }))
        }
    }

    struct TlsAwareGatewayTransport;

    #[async_trait]
    impl NearAiCloudTransport for TlsAwareGatewayTransport {
        async fn get(
            &self,
            request: NearAiCloudRequest,
        ) -> Result<NearAiCloudResponse, ApiTransportReason> {
            assert_eq!(request.url.path(), "/v1/attestation/report");
            assert_eq!(
                request
                    .headers
                    .get(AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer test-key")
            );
            let query = request
                .url
                .query_pairs()
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(
                query.get("signing_algo").map(|value| value.as_ref()),
                Some("ed25519")
            );
            assert_eq!(
                query
                    .get("include_tls_fingerprint")
                    .map(|value| value.as_ref()),
                Some("true")
            );
            let nonce = query.get("nonce").expect("request contains a nonce");
            Ok(NearAiCloudResponse {
                status: 200,
                body: json!({
                    "gateway_attestation": {
                        "request_nonce": nonce,
                        "signing_algo": "ed25519",
                        "signing_address": "22".repeat(32),
                        "intel_quote": "aa",
                        "event_log": [],
                        "tls_cert_fingerprint": "33".repeat(32),
                        "report_data": "00".repeat(64),
                        "info": {"tcb_info": {"app_compose": "{}"}},
                    }
                })
                .to_string(),
                peer_spki_fingerprint: Some("33".repeat(32)),
            })
        }
    }

    fn test_cloud(server: &MockServer) -> NearAiCloudOptions {
        NearAiCloudOptions {
            api_key: "test-key".to_owned(),
            base_url: Url::parse(&format!("{}/v1/", server.uri())).unwrap(),
            transport: std::sync::Arc::new(ReqwestNearAiCloudTransport {
                client: Client::builder().no_proxy().build().unwrap(),
            }),
        }
    }

    fn model_attestation_for_signer(signer: SigningIdentity) -> ModelAttestation {
        ModelAttestation {
            evidence: AttestationEvidence {
                nonce: "11".repeat(32),
                signer,
                intel_quote: "aa".to_owned(),
                event_log: AttestationEventLog::Entries(vec![]),
                app_compose: "{}".to_owned(),
                declared_spki_fingerprint: None,
                reported_quote_data: None,
            },
            nvidia_payload: None,
        }
    }

    #[test]
    fn rejects_null_model_report_data_at_the_response_boundary() {
        let result = parse_model_attestation(
            json!({
                "request_nonce": "11".repeat(32),
                "signing_algo": "ecdsa",
                "signing_address": "22".repeat(20),
                "intel_quote": "aa",
                "event_log": [],
                "report_data": null,
                "info": {"tcb_info": {"app_compose": "{}"}},
            }),
            "model_attestations[0]",
        );
        let error = match result {
            Ok(_) => panic!("a null report_data must be rejected"),
            Err(error) => error,
        };

        assert!(
            matches!(
                error,
                ApiError::InvalidResponse { ref path, .. }
                    if path == "model_attestations[0].report_data"
            ),
            "{error:?}"
        );
    }

    #[test]
    fn gateway_response_requires_report_data() {
        let error = parse_gateway_attestation(json!({}), "gateway_attestation").unwrap_err();

        assert!(matches!(
            error,
            ApiError::InvalidResponse { ref path, .. }
                if path == "gateway_attestation.report_data"
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
            let error = parse_completion_signature_lookup(response).unwrap_err();
            assert!(matches!(error, ApiError::InvalidResponse { .. }));
        }
    }

    #[test]
    fn finder_rejects_malformed_signers_before_matching() {
        let malformed_signature = CompletionSignatureReference {
            kind: CompletionSignatureKind::ProviderTee,
            signer: SigningIdentity {
                signing_algo: SigningAlgo::Ecdsa,
                signing_address: "00".to_owned(),
            },
        };
        let error = find_model_attestation_for_signature(FindModelAttestationForSignatureInput {
            attestations: &[],
            signature: &malformed_signature,
        })
        .unwrap_err();
        assert!(matches!(
            error,
            SdkError::Verification(VerificationError::InvalidInput { ref field, .. })
                if field == "signature.signer.signing_address"
        ));

        let valid_signature = CompletionSignatureReference {
            kind: CompletionSignatureKind::ProviderTee,
            signer: SigningIdentity {
                signing_algo: SigningAlgo::Ecdsa,
                signing_address: "22".repeat(20),
            },
        };
        let malformed_candidate = model_attestation_for_signer(SigningIdentity {
            signing_algo: SigningAlgo::Ecdsa,
            signing_address: "00".to_owned(),
        });
        let error = find_model_attestation_for_signature(FindModelAttestationForSignatureInput {
            attestations: &[malformed_candidate],
            signature: &valid_signature,
        })
        .unwrap_err();
        assert!(matches!(
            error,
            SdkError::Verification(VerificationError::InvalidInput { ref field, .. })
                if field == "attestations[0].signer.signing_address"
        ));
    }

    #[test]
    fn finder_requires_one_matching_attestation() {
        let signature = CompletionSignatureReference {
            kind: CompletionSignatureKind::ProviderTee,
            signer: SigningIdentity {
                signing_algo: SigningAlgo::Ecdsa,
                signing_address: "22".repeat(20),
            },
        };
        let candidate = model_attestation_for_signer(signature.signer.clone());
        let candidates = vec![candidate.clone(), candidate];

        let error = find_model_attestation_for_signature(FindModelAttestationForSignatureInput {
            attestations: &candidates,
            signature: &signature,
        })
        .unwrap_err();

        assert!(matches!(
            error,
            SdkError::Api(ApiError::AmbiguousModelAttestationSigner {
                matching_count: 2,
                total_count: 2,
            })
        ));
    }

    #[test]
    fn cloud_options_reject_invalid_local_input() {
        let result = NearAiCloudOptions::with_base_url("test-key", "http://cloud.example/v1");

        assert!(matches!(
            result,
            Err(VerificationError::InvalidInput { ref field, .. }) if field == "base_url"
        ));
    }

    #[tokio::test]
    async fn fetch_model_attestations_rejects_an_empty_candidate_list() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/attestation/report"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "model_attestations": [],
            })))
            .mount(&server)
            .await;

        let error = fetch_model_attestations(
            &test_cloud(&server),
            FetchModelAttestationsInput {
                model: "glm-5.2",
                signing_algo: None,
                signing_address: None,
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            SdkError::Api(ApiError::UnexpectedModelAttestationCount { actual_count: 0 })
        ));
    }

    #[tokio::test]
    async fn fetch_model_attestations_returns_a_fresh_nonce_and_normalized_evidence() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/attestation/report"))
            .and(query_param("model", "glm-5.2"))
            .and(query_param("provider", "near"))
            .and(header(NO_ALIASING_HEADER, "true"))
            .respond_with(ModelAttestationResponder)
            .mount(&server)
            .await;

        let fetched = fetch_model_attestations(
            &test_cloud(&server),
            FetchModelAttestationsInput {
                model: "glm-5.2",
                signing_algo: None,
                signing_address: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(fetched.attestations.len(), 1);
        assert_eq!(fetched.attestations[0].evidence.nonce, fetched.nonce);
        assert_eq!(fetched.attestations[0].nvidia_payload, None);
    }

    #[tokio::test]
    async fn fetch_model_attestation_for_signature_uses_the_signature_signer() {
        let server = MockServer::start().await;
        let signing_address = "22".repeat(20);
        Mock::given(method("GET"))
            .and(path("/v1/attestation/report"))
            .and(query_param("model", "glm-5.2"))
            .and(query_param("signing_algo", "ecdsa"))
            .and(query_param("signing_address", signing_address.clone()))
            .respond_with(ModelAttestationResponder)
            .mount(&server)
            .await;
        let signature = CompletionSignatureReference {
            kind: CompletionSignatureKind::ProviderTee,
            signer: SigningIdentity {
                signing_algo: SigningAlgo::Ecdsa,
                signing_address,
            },
        };

        let fetched = fetch_model_attestation_for_signature(
            &test_cloud(&server),
            FetchModelAttestationForSignatureInput {
                model: "glm-5.2",
                signature: &signature,
            },
        )
        .await
        .unwrap();

        assert_eq!(fetched.attestation.evidence.signer, signature.signer);
    }

    #[tokio::test]
    async fn fetch_gateway_attestation_requests_tls_bound_evidence() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/attestation/report"))
            .and(query_param("include_tls_fingerprint", "true"))
            .and(query_param("signing_algo", "ed25519"))
            .respond_with(GatewayAttestationResponder)
            .mount(&server)
            .await;

        let fetched = fetch_gateway_attestation(
            &test_cloud(&server),
            FetchGatewayAttestationInput::default(),
        )
        .await
        .unwrap();

        assert_eq!(fetched.attestation.evidence.nonce, fetched.nonce);
        assert_eq!(
            fetched.attestation.evidence.declared_spki_fingerprint,
            Some("33".repeat(32))
        );
        assert_eq!(fetched.peer_spki_fingerprint, None);
    }

    #[tokio::test]
    async fn fetch_gateway_attestation_returns_the_peer_from_a_custom_transport() {
        let cloud = NearAiCloudOptions::with_transport(
            "test-key",
            "https://cloud.example/v1",
            TlsAwareGatewayTransport,
        )
        .unwrap();

        let fetched = fetch_gateway_attestation(&cloud, FetchGatewayAttestationInput::default())
            .await
            .unwrap();

        assert_eq!(fetched.peer_spki_fingerprint, Some("33".repeat(32)));
    }

    #[tokio::test]
    async fn lookup_completion_signature_preserves_kind_and_unavailable_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/signature/found"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "text": "signed",
                "signature": "aa",
                "signing_address": "22".repeat(32),
                "signing_algo": "ed25519",
                "signature_kind": "gateway",
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/signature/pending"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "error_code": "pending",
                "message": "not ready",
            })))
            .mount(&server)
            .await;

        let cloud = test_cloud(&server);
        let found = lookup_completion_signature(
            &cloud,
            FetchCompletionSignatureInput {
                completion_id: "found",
                signing_algo: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            found,
            CompletionSignatureLookup::Found(CompletionSignature {
                kind: CompletionSignatureKind::Gateway,
                ..
            })
        ));

        let fetched = fetch_completion_signature(
            &cloud,
            FetchCompletionSignatureInput {
                completion_id: "found",
                signing_algo: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(fetched.kind, CompletionSignatureKind::Gateway);

        let pending = lookup_completion_signature(
            &cloud,
            FetchCompletionSignatureInput {
                completion_id: "pending",
                signing_algo: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            pending,
            CompletionSignatureLookup::Unavailable(SignatureUnavailable { ref error_code, .. })
                if error_code == "pending"
        ));
    }
}
