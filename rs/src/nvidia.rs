use crate::errors::VerificationError;
use crate::types::NvidiaEvidenceVerifier;
use crate::util::decode_jwt_payload;
use async_trait::async_trait;
use reqwest::Client;
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
        let value: Value =
            response
                .json()
                .await
                .map_err(|_| VerificationError::NrasResponseInvalid {
                    reason: "invalid_json",
                })?;
        let jwt = get_overall_jwt(&value)?;
        let claims =
            decode_jwt_payload(jwt).map_err(|_| VerificationError::NrasResponseInvalid {
                reason: "invalid_jwt",
            })?;
        let claims = claims
            .as_object()
            .ok_or(VerificationError::NrasResponseInvalid {
                reason: "invalid_jwt",
            })?;
        match claims.get("x-nvidia-overall-att-result") {
            Some(Value::Bool(true)) => Ok(()),
            Some(Value::Bool(false)) => {
                Err(VerificationError::GpuAttestationRejected { origin: "nras" })
            }
            _ => Err(VerificationError::NrasResponseInvalid {
                reason: "invalid_verdict_type",
            }),
        }
    }
}

fn get_overall_jwt(value: &Value) -> Result<&str, VerificationError> {
    let first = value
        .as_array()
        .and_then(|items| items.first())
        .and_then(Value::as_array)
        .ok_or(VerificationError::NrasResponseInvalid {
            reason: "invalid_schema",
        })?;
    match (
        first.first().and_then(Value::as_str),
        first.get(1).and_then(Value::as_str),
    ) {
        (Some("JWT"), Some(jwt)) => Ok(jwt),
        _ => Err(VerificationError::NrasResponseInvalid {
            reason: "invalid_schema",
        }),
    }
}
