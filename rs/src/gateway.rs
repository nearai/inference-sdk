use crate::attestation::{verify_dstack_deployment, verify_dstack_quote};
use crate::bindings::{
    verify_report_data_binding, verify_report_data_binding_with_tls_fingerprint,
};
use crate::errors::VerificationError;
use crate::types::{
    AttestationPolicy, AttestationVerifiers, GatewayAttestation, GatewayAttestationPolicy,
    GatewayClientBinding, VerifiedGatewayAttestation,
};

/// Verify NEAR AI Cloud Gateway evidence.
///
/// TLS binding is required by default. When disabled, verification uses the
/// signer-and-nonce report-data layout instead.
pub async fn verify_gateway_attestation(
    attestation: &GatewayAttestation,
    client_binding: &GatewayClientBinding,
    policy: Option<&GatewayAttestationPolicy>,
    verifiers: AttestationVerifiers<'_>,
) -> Result<VerifiedGatewayAttestation, VerificationError> {
    let verify_tls_binding = policy
        .map(|policy| policy.verify_tls_binding)
        .unwrap_or(true);
    let common_policy = policy.map(|policy| AttestationPolicy {
        accepted_tcb_statuses: policy.accepted_tcb_statuses.clone(),
    });
    let verified_quote = verify_dstack_quote(
        &attestation.evidence,
        &client_binding.nonce,
        common_policy.as_ref(),
        verifiers.quote,
        Some(&attestation.reported_quote_data),
    )
    .await?;
    let tls_binding = if verify_tls_binding {
        let peer_spki_fingerprint = client_binding
            .peer_spki_fingerprint
            .as_deref()
            .ok_or(VerificationError::TlsBindingRequired)?;
        let spki_fingerprint = verify_report_data_binding_with_tls_fingerprint(
            &verified_quote.quote.report_data,
            &client_binding.nonce,
            &verified_quote.signer.signing_address,
            attestation.tls_spki_fingerprint.as_deref(),
            peer_spki_fingerprint,
        )?;
        crate::types::GatewayTlsBinding::Attested { spki_fingerprint }
    } else {
        verify_report_data_binding(
            &verified_quote.quote.report_data,
            &client_binding.nonce,
            &verified_quote.signer.signing_address,
        )?;
        crate::types::GatewayTlsBinding::None
    };
    let evidence = verify_dstack_deployment(&verified_quote, verifiers.deployment).await?;
    Ok(VerifiedGatewayAttestation {
        evidence,
        tls_binding,
    })
}
