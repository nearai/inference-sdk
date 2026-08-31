"""NEAR AI Cloud Gateway attestation verification."""

from __future__ import annotations

from ..types.attestation_gateway import GatewayAttestation
from ..types.verification import (
    AttestationVerifiers,
    GatewayAttestationPolicy,
    GatewayClientBinding,
    GatewayTlsBinding,
    VerifiedGatewayAttestation,
)
from ..utils.errors import verification_failure
from .attestation_common import (
    verify_report_data_binding,
    verify_report_data_binding_with_tls_fingerprint,
)
from .dstack_attestation import verify_dstack_deployment, verify_dstack_quote


async def verify_gateway_attestation(
    attestation: GatewayAttestation,
    client_binding: GatewayClientBinding,
    *,
    policy: GatewayAttestationPolicy | None = None,
    verifiers: AttestationVerifiers | None = None,
) -> VerifiedGatewayAttestation:
    """Verify Gateway evidence and, when enabled, its quote-bound TLS identity.

    TLS binding is enabled by default. When disabled, the signer-and-nonce
    report-data layout is verified instead.
    """

    verify_tls_binding = True if policy is None else policy.verify_tls_binding

    verified_quote = await verify_dstack_quote(
        attestation=attestation,
        advertised_report_data=attestation.reported_quote_data,
        nonce=client_binding.nonce,
        policy=policy,
        quote_verifier=None if verifiers is None else verifiers.quote,
    )
    if verify_tls_binding:
        peer_tls_spki_fingerprint = client_binding.peer_spki_fingerprint
        if peer_tls_spki_fingerprint is None:
            raise verification_failure('policy.tls_binding_required')
        spki_fingerprint = verify_report_data_binding_with_tls_fingerprint(
            report_data=verified_quote.quote.report_data,
            nonce=client_binding.nonce,
            signer=verified_quote.signer,
            reported_tls_spki_fingerprint=attestation.tls_spki_fingerprint,
            peer_tls_spki_fingerprint=peer_tls_spki_fingerprint,
        )
        tls_binding = GatewayTlsBinding(
            kind='attested', spki_fingerprint=spki_fingerprint
        )
    else:
        verify_report_data_binding(
            report_data=verified_quote.quote.report_data,
            nonce=client_binding.nonce,
            signer=verified_quote.signer,
        )
        tls_binding = GatewayTlsBinding(kind='none')
    evidence = await verify_dstack_deployment(
        verified_quote, None if verifiers is None else verifiers.deployment
    )
    return VerifiedGatewayAttestation(
        signer=evidence.signer,
        tcb_status=evidence.tcb_status,
        advisory_ids=evidence.advisory_ids,
        deployment=evidence.deployment,
        deployment_provenance=evidence.deployment_provenance,
        tls_binding=tls_binding,
    )
