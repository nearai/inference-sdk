use crate::attestation::{verify_dstack_deployment, verify_dstack_quote};
use crate::bindings::verify_gateway_report_data_binding;
use crate::errors::VerificationError;
use crate::types::{
    AttestationPolicy, AttestationVerifiers, GatewayAttestation, VerifiedGatewayAttestation,
};

/// Verify NEAR AI Cloud Gateway evidence and bind it to the TLS SPKI
/// fingerprint independently observed by the caller for that attestation
/// request.
pub async fn verify_gateway_attestation(
    attestation: &GatewayAttestation,
    nonce: &str,
    peer_spki_fingerprint: &str,
    policy: Option<&AttestationPolicy>,
    verifiers: AttestationVerifiers<'_>,
) -> Result<VerifiedGatewayAttestation, VerificationError> {
    let verified_quote = verify_dstack_quote(
        &attestation.evidence,
        nonce,
        policy,
        verifiers.quote,
        Some(&attestation.reported_quote_data),
    )
    .await?;
    let tls_binding = verify_gateway_report_data_binding(
        &verified_quote.quote.report_data,
        nonce,
        &verified_quote.signer.signing_address,
        verified_quote
            .attestation
            .declared_spki_fingerprint
            .as_deref(),
        peer_spki_fingerprint,
    )?;
    let evidence = verify_dstack_deployment(&verified_quote, verifiers.deployment).await?;
    Ok(VerifiedGatewayAttestation {
        evidence,
        tls_binding,
    })
}
