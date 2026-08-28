use crate::attestation::{verify_dstack_deployment, verify_dstack_quote};
use crate::bindings::{verify_cloud_model_report_data_binding, verify_reported_nonce};
use crate::errors::VerificationError;
use crate::nvidia::NrasNvidiaEvidenceVerifier;
use crate::types::{
    AttestationPolicy, GpuEvidenceRequirement, GpuEvidenceStatus, NvidiaEvidenceVerifier,
    VerifiedModelAttestation, VerifyModelAttestationInput,
};
use serde_json::Value;

/// Verify model evidence returned through NEAR AI Cloud. A successful model
/// verification establishes the model signing identity and deployment
/// measurements, but not a client-to-model TLS connection: the client talks to
/// the Cloud Gateway rather than the upstream model CVM.
pub async fn verify_model_attestation(
    input: VerifyModelAttestationInput<'_>,
) -> Result<VerifiedModelAttestation, VerificationError> {
    let common_policy = input.policy.map(|policy| AttestationPolicy {
        accepted_tcb_statuses: policy.accepted_tcb_statuses.clone(),
    });
    let verified_quote = verify_dstack_quote(
        &input.attestation.evidence,
        input.nonce,
        common_policy.as_ref(),
        input.verifiers.quote,
        input.attestation.evidence.reported_quote_data.as_deref(),
    )
    .await?;
    let tls_binding = verify_cloud_model_report_data_binding(
        &verified_quote.quote.report_data,
        input.nonce,
        &verified_quote.signer.signing_address,
        verified_quote
            .attestation
            .declared_spki_fingerprint
            .as_deref(),
    )?;
    let evidence = verify_dstack_deployment(&verified_quote, input.verifiers.deployment).await?;
    let gpu_evidence = verify_nvidia_evidence(
        input.attestation.nvidia_payload.as_deref(),
        input.nonce,
        input
            .policy
            .map(|policy| policy.gpu_evidence)
            .unwrap_or(GpuEvidenceRequirement::IfPresent),
        input.verifiers.nvidia,
    )
    .await?;
    Ok(VerifiedModelAttestation {
        evidence,
        tls_binding,
        gpu_evidence,
    })
}

async fn verify_nvidia_evidence(
    payload: Option<&str>,
    nonce: &str,
    requirement: GpuEvidenceRequirement,
    verifier: Option<&dyn NvidiaEvidenceVerifier>,
) -> Result<GpuEvidenceStatus, VerificationError> {
    let Some(payload) = payload else {
        return match requirement {
            GpuEvidenceRequirement::IfPresent => Ok(GpuEvidenceStatus::NotProvided),
            GpuEvidenceRequirement::Required => Err(VerificationError::GpuEvidenceRequired),
        };
    };
    let parsed: Value =
        serde_json::from_str(payload).map_err(|_| VerificationError::GpuPayloadInvalid {
            reason: "invalid_json",
        })?;
    let reported_nonce = parsed
        .as_object()
        .and_then(|object| object.get("nonce"))
        .and_then(Value::as_str)
        .ok_or(VerificationError::GpuPayloadInvalid {
            reason: "nonce_missing",
        })?;
    verify_reported_nonce(reported_nonce, nonce, "nvidia_payload")?;

    let default_verifier = NrasNvidiaEvidenceVerifier::default();
    let verifier = verifier.unwrap_or(&default_verifier);
    verifier.verify(payload).await?;
    Ok(GpuEvidenceStatus::Verified)
}
