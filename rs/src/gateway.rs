use crate::attestation::{verify_dstack_deployment, verify_dstack_quote};
use crate::bindings::{
    verify_report_data_binding, verify_report_data_binding_with_tls_fingerprint,
};
use crate::deployment_verifier::run_deployment_verifier;
use crate::errors::VerificationError;
use crate::types::{
    AttestationPolicy, AttestationVerifiers, GatewayAttestation, GatewayClientBinding,
    VerifiedAttestationEvidence, VerifiedGatewayAttestation,
};

/// Verify NEAR AI Cloud Gateway evidence.
///
/// An attestation with a reported SPKI fingerprint uses the TLS-bound
/// report-data layout. One without it uses the signer-and-nonce layout.
pub async fn verify_gateway_attestation(
    attestation: &GatewayAttestation,
    client_binding: &GatewayClientBinding,
    policy: Option<&AttestationPolicy>,
    verifiers: AttestationVerifiers<'_>,
) -> Result<VerifiedGatewayAttestation, VerificationError> {
    let verified_quote = verify_dstack_quote(
        &attestation.evidence,
        &client_binding.nonce,
        policy,
        verifiers.tdx_quote,
        Some(&attestation.reported_quote_data),
    )
    .await?;
    let tls_binding =
        if let Some(reported_spki_fingerprint) = attestation.spki_fingerprint.as_deref() {
            let peer_spki_fingerprint = client_binding
                .spki_fingerprint
                .as_deref()
                .ok_or(VerificationError::SpkiFingerprintRequired)?;
            let spki_fingerprint = verify_report_data_binding_with_tls_fingerprint(
                &verified_quote.quote.report_data,
                &client_binding.nonce,
                &verified_quote.signer.signing_address,
                reported_spki_fingerprint,
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
    let deployment = verify_dstack_deployment(&verified_quote)?;
    let deployment_provenance = run_deployment_verifier(&deployment, verifiers.deployment).await?;
    let evidence = VerifiedAttestationEvidence {
        signer: verified_quote.signer,
        tcb_status: verified_quote.quote.tcb_status,
        advisory_ids: verified_quote.quote.advisory_ids,
        deployment,
        deployment_provenance,
    };
    Ok(VerifiedGatewayAttestation {
        evidence,
        tls_binding,
    })
}
