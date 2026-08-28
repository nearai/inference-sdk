use crate::errors::VerificationError;
use crate::types::NvidiaEvidenceVerifier;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

pub const DEFAULT_NVIDIA_NRAS_URL: &str = "https://nras.attestation.nvidia.com/v3/attest/gpu";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default NVIDIA adapter. It submits the payload to NRAS over HTTPS and
/// accepts only NRAS's documented boolean overall result. It does not perform
/// local JWT/EAT signature verification; provide a custom verifier when that
/// trust model is required.
#[derive(Clone, Debug)]
pub struct NrasNvidiaEvidenceVerifier {
    client: Client,
    url: String,
}

impl Default for NrasNvidiaEvidenceVerifier {
    fn default() -> Self {
        Self::new(DEFAULT_NVIDIA_NRAS_URL)
    }
}

impl NrasNvidiaEvidenceVerifier {
    pub fn new(url: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .expect("default reqwest client configuration is valid");
        Self {
            client,
            url: url.into(),
        }
    }

    pub fn with_client(client: Client, url: impl Into<String>) -> Self {
        Self {
            client,
            url: url.into(),
        }
    }
}

#[async_trait]
impl NvidiaEvidenceVerifier for NrasNvidiaEvidenceVerifier {
    async fn verify(&self, nvidia_payload: &str) -> Result<(), VerificationError> {
        let response = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(nvidia_payload.to_owned())
            .send()
            .await
            .map_err(|error| VerificationError::NrasRequestFailed {
                reason: if error.is_timeout() {
                    "timeout"
                } else {
                    "transport"
                },
                status: None,
                retryable: true,
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(VerificationError::NrasRequestFailed {
                reason: "http_status",
                status: Some(status.as_u16()),
                retryable: status.as_u16() == 408
                    || status.as_u16() == 429
                    || status.is_server_error(),
            });
        }
        // Keep HTTP JSON decoding separate from NRAS wire decoding so an
        // invalid JSON document and an invalid NRAS envelope remain distinct
        // public failures.
        let raw: Value =
            response
                .json()
                .await
                .map_err(|_| VerificationError::NrasResponseInvalid {
                    reason: "invalid_json",
                })?;
        let jwt = decode_nras_overall_attestation_jwt(raw)?;
        if decode_nras_overall_attestation_verdict(&jwt)? {
            Ok(())
        } else {
            Err(VerificationError::GpuAttestationRejected { origin: "nras" })
        }
    }
}

/// NRAS returns a heterogeneous list. Only the first entry is part of the
/// contract consumed by this SDK; later entries remain intentionally opaque.
#[derive(Deserialize)]
#[serde(transparent)]
struct NrasResponseWire(Vec<Value>);

/// The first NRAS entry is also extensible. Decode it as an array and consume
/// only the documented `JWT` and token prefix.
#[derive(Deserialize)]
#[serde(transparent)]
struct NrasJwtEntryWire(Vec<Value>);

#[derive(Deserialize)]
struct NrasOverallAttestationJwtClaimsWire {
    #[serde(rename = "x-nvidia-overall-att-result")]
    overall_attestation_result: bool,
}

fn decode_nras_overall_attestation_jwt(raw: Value) -> Result<String, VerificationError> {
    let NrasResponseWire(entries) =
        serde_json::from_value(raw).map_err(|_| invalid_nras_response("invalid_schema"))?;
    let first = entries
        .into_iter()
        .next()
        .ok_or_else(|| invalid_nras_response("invalid_schema"))?;
    let NrasJwtEntryWire(entry) =
        serde_json::from_value(first).map_err(|_| invalid_nras_response("invalid_schema"))?;
    match (
        entry.first().and_then(Value::as_str),
        entry.get(1).and_then(Value::as_str),
    ) {
        (Some("JWT"), Some(jwt)) => Ok(jwt.to_owned()),
        _ => Err(invalid_nras_response("invalid_schema")),
    }
}

fn decode_nras_overall_attestation_verdict(jwt: &str) -> Result<bool, VerificationError> {
    let payload = decode_nras_jwt_payload(jwt)?;
    if !payload.is_object() {
        return Err(invalid_nras_response("invalid_jwt"));
    }
    let claims: NrasOverallAttestationJwtClaimsWire = serde_json::from_value(payload)
        .map_err(|_| invalid_nras_response("invalid_verdict_type"))?;
    Ok(claims.overall_attestation_result)
}

fn decode_nras_jwt_payload(jwt: &str) -> Result<Value, VerificationError> {
    use base64::Engine;

    let mut parts = jwt.split('.');
    let _header = parts
        .next()
        .ok_or_else(|| invalid_nras_response("invalid_jwt"))?;
    let payload = parts
        .next()
        .ok_or_else(|| invalid_nras_response("invalid_jwt"))?;
    let _signature = parts
        .next()
        .ok_or_else(|| invalid_nras_response("invalid_jwt"))?;
    if parts.next().is_some() {
        return Err(invalid_nras_response("invalid_jwt"));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid_nras_response("invalid_jwt"))?;
    serde_json::from_slice(&bytes).map_err(|_| invalid_nras_response("invalid_jwt"))
}

fn invalid_nras_response(reason: &'static str) -> VerificationError {
    VerificationError::NrasResponseInvalid { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;

    #[test]
    fn accepts_the_required_nras_jwt_prefix_and_ignores_extensions() {
        let jwt = jwt_with_payload(json!({
            "x-nvidia-overall-att-result": true,
            "extra_claim": "ignored",
        }));
        let raw = json!([
            ["JWT", jwt, {"extra_entry_value": true}],
            {"later_entry": "ignored"},
        ]);

        let jwt = decode_nras_overall_attestation_jwt(raw).unwrap();
        assert!(decode_nras_overall_attestation_verdict(&jwt).unwrap());
    }

    #[test]
    fn rejects_an_invalid_nras_jwt_envelope() {
        let error = decode_nras_overall_attestation_jwt(json!([["TOKEN", "value"]])).unwrap_err();

        assert!(matches!(
            error,
            VerificationError::NrasResponseInvalid {
                reason: "invalid_schema"
            }
        ));
    }

    #[test]
    fn distinguishes_invalid_jwt_payloads_from_invalid_verdicts() {
        let error = decode_nras_overall_attestation_verdict("not-a-jwt").unwrap_err();
        assert!(matches!(
            error,
            VerificationError::NrasResponseInvalid {
                reason: "invalid_jwt"
            }
        ));

        let jwt = jwt_with_payload(json!({
            "x-nvidia-overall-att-result": "PASS",
        }));
        let error = decode_nras_overall_attestation_verdict(&jwt).unwrap_err();
        assert!(matches!(
            error,
            VerificationError::NrasResponseInvalid {
                reason: "invalid_verdict_type"
            }
        ));
    }

    fn jwt_with_payload(payload: Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        format!("{header}.{payload}.signature")
    }
}
