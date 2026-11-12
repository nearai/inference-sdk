//! Experimental Direct endpoint inference and attestation verification.
use crate::*;
use crate::{
    errors::protocol,
    inference_core::{
        input, ordinary_client, verified_at, CoreOptions, EvidenceApi, InferenceCore,
        PolicyVerifier, Session, SessionProvider, VerifiedReceipt,
    },
    util::{decode_hex, generate_nonce, require_hex_length},
};
use reqwest::header::HeaderMap;
use std::{sync::Arc, time::Duration};
#[derive(Clone, Debug, PartialEq)]
pub struct DirectModelAttestation {
    pub attestation: ModelAttestation,
    pub model_name: String,
    pub instance_id: Option<String>,
    pub spki_fingerprint: Option<String>,
}
#[derive(Clone, Debug)]
pub struct DirectClientBinding {
    pub nonce: String,
    pub spki_fingerprint: Option<String>,
}
#[derive(Clone, Debug)]
pub struct FetchedDirectModelAttestations {
    pub serving_attestation: DirectModelAttestation,
    pub attestations: Vec<DirectModelAttestation>,
    pub client_binding: DirectClientBinding,
    pub ohttp_attestation: Option<OhttpAttestation>,
}
/// The quote does not authenticate the endpoint's `model_name` or `instance_id`.
#[derive(Clone, Debug)]
pub struct VerifiedDirectModelAttestation {
    pub attestation: VerifiedModelAttestation,
    pub model_name: String,
    pub instance_id: Option<String>,
    pub spki_fingerprint: Option<String>,
}
#[derive(Clone, Debug)]
pub struct DirectAttestationVerificationResult {
    pub serving_attestation: VerifiedDirectModelAttestation,
    pub attestations: Vec<VerifiedDirectModelAttestation>,
    pub tls_binding: GatewayTlsBinding,
    pub spki_fingerprints: Vec<String>,
    pub verified_at: u64,
}
/// A Direct client's receipt with every verified report sharing its selected signer.
#[derive(Clone, Debug)]
pub struct VerifiedDirectCompletionResult {
    pub id: String,
    pub signature: CompletionSignature,
    /// The request's verified reports matching its selected signing key.
    pub attestations: Vec<VerifiedDirectModelAttestation>,
}
impl VerifiedDirectCompletionResult {
    pub fn signature_kind(&self) -> CompletionSignatureKind {
        self.signature.kind
    }
}
#[derive(Clone)]
pub struct DirectAttestationClient {
    api: AttestationClient,
}

pub struct DirectAttestationFetchOptions<'a> {
    pub signing_algo: Option<SigningAlgo>,
    pub signing_address: Option<&'a str>,
    pub include_spki_fingerprint: bool,
}

impl Default for DirectAttestationFetchOptions<'_> {
    fn default() -> Self {
        Self {
            signing_algo: None,
            signing_address: None,
            include_spki_fingerprint: true,
        }
    }
}

impl DirectAttestationClient {
    pub fn new(base_url: &str, api_key: Option<String>) -> Result<Self, ApiError> {
        Ok(Self {
            api: AttestationClient::with_base_url(api_key, base_url)?,
        })
    }
    pub fn with_headers(mut self, headers: reqwest::header::HeaderMap) -> Self {
        self.api = self.api.with_headers(headers);
        self
    }
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.api = self.api.with_http_client(client);
        self
    }
    pub async fn fetch_model_attestations(
        &self,
        algo: Option<SigningAlgo>,
        address: Option<&str>,
    ) -> Result<FetchedDirectModelAttestations, ApiError> {
        self.fetch_model_attestations_with_options(DirectAttestationFetchOptions {
            signing_algo: algo,
            signing_address: address,
            ..Default::default()
        })
        .await
    }

    pub async fn fetch_model_attestations_with_options(
        &self,
        options: DirectAttestationFetchOptions<'_>,
    ) -> Result<FetchedDirectModelAttestations, ApiError> {
        let DirectAttestationFetchOptions {
            signing_algo: algo,
            signing_address: address,
            include_spki_fingerprint,
        } = options;
        if let Some(address) = address {
            crate::cloud_api::validate_input_signing_address(address, algo, "signing_address")?;
        }
        let nonce = generate_nonce();
        let mut query = vec![
            ("nonce", nonce.clone()),
            (
                "include_tls_fingerprint",
                include_spki_fingerprint.to_string(),
            ),
        ];
        if let Some(algo) = algo {
            query.push(("signing_algo", algo.to_string()));
        }
        if let Some(address) = address {
            query.push(("signing_address", address.into()));
        }
        let (value, peer_spki_fingerprint) = self
            .api
            .fetch_value(
                "attestation/report",
                &query,
                ApiResource::ModelAttestation,
                include_spki_fingerprint,
            )
            .await?;
        let serving = decode(&value)?;
        let reports = value
            .get("all_attestations")
            .and_then(serde_json::Value::as_array)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| invalid("all_attestations"))?;
        let mut attestations = reports
            .iter()
            .map(decode)
            .collect::<Result<Vec<_>, ApiError>>()?;
        let mut bare = serving.clone();
        bare.attestation.compose_manager_attestation = None;
        let index = attestations
            .iter()
            .position(|report| {
                let mut report = report.clone();
                report.attestation.compose_manager_attestation = None;
                report == bare
            })
            .ok_or_else(|| invalid("serving_attestation"))?;
        if attestations[index]
            .attestation
            .compose_manager_attestation
            .is_none()
        {
            attestations[index].attestation.compose_manager_attestation =
                serving.attestation.compose_manager_attestation;
        }
        for item in &attestations {
            if item.spki_fingerprint.is_some() != include_spki_fingerprint {
                return Err(invalid("tls_cert_fingerprint"));
            }
            if decode_hex(&item.attestation.evidence.nonce).ok() != decode_hex(&nonce).ok() {
                return Err(ApiError::NonceMismatch {
                    resource: ApiResource::ModelAttestation,
                });
            }
        }
        let ohttp_attestation = value
            .get("ohttp_attestation")
            .filter(|v| !v.is_null())
            .map(|v| serde_json::from_value(v.clone()).map_err(|_| invalid("ohttp_attestation")))
            .transpose()?;
        Ok(FetchedDirectModelAttestations {
            serving_attestation: attestations[index].clone(),
            attestations,
            client_binding: DirectClientBinding {
                nonce,
                spki_fingerprint: peer_spki_fingerprint,
            },
            ohttp_attestation,
        })
    }
    pub async fn fetch_completion_signature(
        &self,
        id: &str,
        algo: Option<SigningAlgo>,
    ) -> Result<CompletionSignature, ApiError> {
        self.api.direct_signature(id, algo).await
    }
}
fn invalid(path: &str) -> ApiError {
    ApiError::InvalidResponse {
        path: path.into(),
        expected: "documented direct attestation shape".into(),
        actual: "missing or invalid".into(),
    }
}
fn decode(value: &serde_json::Value) -> Result<DirectModelAttestation, ApiError> {
    let model_name = value
        .get("model_name")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("model_name"))?
        .into();
    let optional =
        |value: Option<&serde_json::Value>, name: &str| -> Result<Option<String>, ApiError> {
            match value {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
                _ => Err(invalid(name)),
            }
        };
    Ok(DirectModelAttestation {
        attestation: crate::cloud_api::decode_model_value(value)?,
        model_name,
        instance_id: optional(
            value.get("info").and_then(|v| v.get("instance_id")),
            "instance_id",
        )?,
        spki_fingerprint: optional(value.get("tls_cert_fingerprint"), "tls_cert_fingerprint")?,
    })
}
pub async fn verify_direct_model_attestation(
    attestation: &DirectModelAttestation,
    binding: &ModelClientBinding,
    policy: Option<&ModelAttestationPolicy>,
    verifiers: ModelAttestationVerifiers<'_>,
) -> Result<VerifiedDirectModelAttestation, VerificationError> {
    let verified = crate::model::verify_model_with_tls(
        &attestation.attestation,
        binding,
        policy,
        verifiers,
        attestation.spki_fingerprint.as_deref(),
    )
    .await?;
    let fingerprint = attestation
        .spki_fingerprint
        .as_ref()
        .map(|s| {
            require_hex_length(s, 32)
                .map(hex::encode)
                .map_err(|_| protocol("input.invalid", "invalid TLS fingerprint"))
        })
        .transpose()?;
    Ok(VerifiedDirectModelAttestation {
        attestation: verified,
        model_name: attestation.model_name.clone(),
        instance_id: attestation.instance_id.clone(),
        spki_fingerprint: fingerprint,
    })
}
pub async fn verify_direct_model_attestations(
    fetched: &FetchedDirectModelAttestations,
    policy: Option<&ModelAttestationPolicy>,
    verifiers: ModelAttestationVerifiers<'_>,
) -> Result<DirectAttestationVerificationResult, VerificationError> {
    if fetched.attestations.is_empty() {
        return Err(protocol(
            "policy.model_attestation_required",
            "empty report set",
        ));
    }
    let index = fetched
        .attestations
        .iter()
        .position(|v| v == &fetched.serving_attestation)
        .ok_or_else(|| protocol("input.invalid", "serving report missing from report set"))?;
    let binding = ModelClientBinding {
        nonce: fetched.client_binding.nonce.clone(),
    };
    let attestations =
        futures_util::future::try_join_all(fetched.attestations.iter().map(|report| {
            verify_direct_model_attestation(
                report,
                &binding,
                policy,
                ModelAttestationVerifiers {
                    tdx_quote: verifiers.tdx_quote,
                    deployment: verifiers.deployment,
                    gpu_evidence: verifiers.gpu_evidence,
                },
            )
        }))
        .await?;
    let serving = attestations[index].clone();
    let tls_binding = if let Some(pin) = &serving.spki_fingerprint {
        let peer = fetched
            .client_binding
            .spki_fingerprint
            .as_ref()
            .ok_or(VerificationError::SpkiFingerprintRequired)?;
        if decode_hex(pin).ok() != decode_hex(peer).ok() {
            return Err(VerificationError::SpkiFingerprintMismatch);
        }
        GatewayTlsBinding::Attested {
            spki_fingerprint: pin.clone(),
        }
    } else {
        GatewayTlsBinding::None
    };
    let mut spki_fingerprints = Vec::new();
    for report in &attestations {
        if let Some(pin) = &report.spki_fingerprint {
            if !spki_fingerprints.contains(pin) {
                spki_fingerprints.push(pin.clone());
            }
        }
    }
    Ok(DirectAttestationVerificationResult {
        serving_attestation: serving,
        attestations,
        tls_binding,
        spki_fingerprints,
        verified_at: verified_at(),
    })
}
pub fn verify_direct_model_response(
    request: &[u8],
    response: &[u8],
    signature: &CompletionSignature,
    attestations: &[VerifiedDirectModelAttestation],
) -> Result<Vec<VerifiedDirectModelAttestation>, VerificationError> {
    if signature.kind != CompletionSignatureKind::ProviderTee {
        return Err(VerificationError::SignatureKindMismatch {
            expected: CompletionSignatureKind::ProviderTee,
            actual: signature.kind,
        });
    }
    let matching: Vec<_> = attestations
        .iter()
        .filter(|a| {
            a.attestation.evidence.signer.signing_algo == signature.signer.signing_algo
                && decode_hex(&a.attestation.evidence.signer.signing_address).ok()
                    == decode_hex(&signature.signer.signing_address).ok()
        })
        .cloned()
        .collect();
    let first = matching
        .first()
        .ok_or(VerificationError::SignatureSignerMismatch)?;
    verify_model_response(request, response, signature, &first.attestation)?;
    Ok(matching)
}
#[derive(Clone)]
pub struct DirectInferenceClientOptions {
    pub api_key: Option<String>,
    pub base_url: String,
    pub headers: HeaderMap,
    pub e2ee: bool,
    pub ohttp: bool,
    pub signing_algo: SigningAlgo,
    pub include_spki_fingerprint: bool,
    pub attestation_cache_ttl: Duration,
    pub response_cache_ttl: Duration,
    pub model_verification: ModelVerificationOptions,
    pub deployment_policy: Option<Arc<dyn DeploymentPolicy>>,
}
impl Default for DirectInferenceClientOptions {
    fn default() -> Self {
        let options = CoreOptions::default();
        Self {
            api_key: options.api_key,
            base_url: String::new(),
            headers: options.headers,
            e2ee: options.e2ee,
            ohttp: options.ohttp,
            signing_algo: options.signing_algo,
            include_spki_fingerprint: true,
            attestation_cache_ttl: options.attestation_cache_ttl,
            response_cache_ttl: options.response_cache_ttl,
            model_verification: options.model_verification,
            deployment_policy: options.deployment_policy,
        }
    }
}
impl From<DirectInferenceClientOptions> for CoreOptions {
    fn from(options: DirectInferenceClientOptions) -> Self {
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
pub struct DirectInferenceClient {
    core: InferenceCore,
}
impl DirectInferenceClient {
    pub fn new(base_url: String, api_key: Option<String>) -> Result<Self, InferenceError> {
        Self::with_options(DirectInferenceClientOptions {
            base_url,
            api_key,
            ..Default::default()
        })
    }
    pub fn with_options(options: DirectInferenceClientOptions) -> Result<Self, InferenceError> {
        let provider = SessionProvider::Direct {
            include_spki_fingerprint: options.include_spki_fingerprint,
        };
        Ok(Self {
            core: InferenceCore::new(options.into(), provider)?,
        })
    }
    pub async fn verify(
        &self,
        model: &str,
    ) -> Result<DirectAttestationVerificationResult, InferenceError> {
        self.core
            .session(model)
            .await?
            .direct
            .clone()
            .ok_or_else(|| input("client", "expected direct client").into())
    }
    pub fn base_url(&self) -> &str {
        self.core.base_url()
    }
    /// Clear captured response verification records.
    pub async fn clear_response_cache(&self) {
        self.core.clear_response_cache().await;
    }
    pub fn chat_request(
        &self,
        body: serde_json::Value,
    ) -> Result<reqwest::Request, InferenceError> {
        self.core.chat_request(body)
    }
    pub async fn chat_completions(
        &self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, InferenceError> {
        self.core.chat_completions(body).await
    }
    pub async fn send(
        &self,
        request: reqwest::Request,
    ) -> Result<InferenceResponse, InferenceError> {
        self.core.send(request).await
    }
    pub async fn verify_response(
        &self,
        id: &str,
    ) -> Result<VerifiedDirectCompletionResult, InferenceError> {
        match self.core.verify_receipt(id).await? {
            VerifiedReceipt::Direct(receipt) => Ok(receipt),
            VerifiedReceipt::Gateway(_) => unreachable!("Direct client contains a Gateway receipt"),
        }
    }
}
pub(crate) async fn create_session(
    model: &str,
    options: CoreOptions,
    include_spki_fingerprint: bool,
) -> Result<Arc<Session>, InferenceError> {
    let api = DirectAttestationClient::new(&options.base_url, options.api_key.clone())?
        .with_headers(options.headers.clone());
    let fetched = api
        .fetch_model_attestations_with_options(DirectAttestationFetchOptions {
            signing_algo: Some(options.signing_algo),
            include_spki_fingerprint,
            ..Default::default()
        })
        .await?;
    let o = &options.model_verification;
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
    let verified = verify_direct_model_attestations(
        &fetched,
        o.policy.as_ref(),
        ModelAttestationVerifiers {
            tdx_quote: o.tdx_quote.as_deref(),
            gpu_evidence: o.gpu_evidence.as_deref(),
            deployment,
        },
    )
    .await?;
    let serving = &verified.serving_attestation.attestation.evidence.signer;
    let tls_bound = matches!(verified.tls_binding, GatewayTlsBinding::Attested { .. });
    let selected = verified
        .attestations
        .iter()
        .map(|a| &a.attestation)
        .find(|a| {
            a.evidence.signer.signing_algo == options.signing_algo
                && a.signing_public_key.is_some()
                && (!(options.ohttp || tls_bound) || same_signer(&a.evidence.signer, serving))
        })
        .cloned()
        .ok_or_else(|| protocol("e2ee.model_public_key_required", "no matching model key"))?;
    let selected_direct_attestations: Vec<_> = verified
        .attestations
        .iter()
        .filter(|a| same_signer(&a.attestation.evidence.signer, &selected.evidence.signer))
        .cloned()
        .collect();
    let pins: Vec<_> = selected_direct_attestations
        .iter()
        .filter_map(|a| a.spki_fingerprint.clone())
        .collect();
    let client = if tls_bound {
        create_pinned_tls_client(&pins)?
    } else {
        ordinary_client()?
    };
    let ohttp = if options.ohttp {
        let raw = fetched.ohttp_attestation.as_ref().ok_or_else(|| {
            protocol(
                "ohttp.attestation_required",
                "direct endpoint omitted OHTTP evidence",
            )
        })?;
        let config = verify_ohttp_key_config(raw, serving)?;
        Some(create_ohttp_client(
            &config,
            &options.base_url,
            client.clone(),
            options.headers.keys().map(|k| k.to_string()).collect(),
        )?)
    } else {
        None
    };
    Ok(Arc::new(Session {
        gateway: None,
        models: Vec::new(),
        selected_direct_attestations,
        selected: Some(selected),
        verified_at: verified.verified_at,
        direct: Some(verified),
        client: client.clone(),
        api: EvidenceApi::Direct(api.with_http_client(client)),
        ohttp,
    }))
}

// Reports may spell the same validated hexadecimal address differently.
pub(crate) fn same_signer(left: &SigningIdentity, right: &SigningIdentity) -> bool {
    left.signing_algo == right.signing_algo
        && matches!(
            (decode_hex(&left.signing_address), decode_hex(&right.signing_address)),
            (Ok(left), Ok(right)) if left == right
        )
}
