use crate::attestation::{verify_dstack_deployment, verify_dstack_quote};
use crate::bindings::verify_gateway_report_data_binding;
use crate::errors::VerificationError;
use crate::types::{
    AttestationPolicy, AttestationVerifiers, GatewayAttestation, GatewayAttestationPolicy,
    GatewayClientBinding, VerifiedGatewayAttestation,
};

/// Verify NEAR AI Cloud Gateway evidence and bind it to the TLS SPKI
/// fingerprint independently observed by the caller for that attestation request.
///
/// Peer TLS binding is required by default. Set
/// [`GatewayAttestationPolicy::verify_peer_tls_binding`] to `false` only when
/// the runtime cannot expose the peer certificate for the evidence request.
pub async fn verify_gateway_attestation(
    attestation: &GatewayAttestation,
    client_binding: &GatewayClientBinding,
    policy: Option<&GatewayAttestationPolicy>,
    verifiers: AttestationVerifiers<'_>,
) -> Result<VerifiedGatewayAttestation, VerificationError> {
    let verify_peer_tls_binding = policy
        .map(|policy| policy.verify_peer_tls_binding)
        .unwrap_or(true);
    if verify_peer_tls_binding && client_binding.peer_spki_fingerprint.is_none() {
        return Err(VerificationError::PeerTlsBindingRequired);
    }
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
    let peer_spki_fingerprint = if verify_peer_tls_binding {
        client_binding.peer_spki_fingerprint.as_deref()
    } else {
        None
    };
    let tls_binding = verify_gateway_report_data_binding(
        &verified_quote.quote.report_data,
        &client_binding.nonce,
        &verified_quote.signer.signing_address,
        &attestation.declared_spki_fingerprint,
        peer_spki_fingerprint,
    )?;
    let evidence = verify_dstack_deployment(&verified_quote, verifiers.deployment).await?;
    Ok(VerifiedGatewayAttestation {
        evidence,
        tls_binding,
    })
}
