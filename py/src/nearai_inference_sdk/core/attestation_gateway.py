"""NEAR AI Cloud Gateway attestation verification."""

from __future__ import annotations

from ..types.attestation_gateway import GatewayAttestation
from ..types.verification import (
    AttestationPolicy,
    AttestationVerifiers,
    GatewayClientBinding,
    GatewayTlsBinding,
    VerifiedGatewayAttestation,
)
from ..utils.errors import verification_failure
from .attestation_common import (
    verify_peer_spki_fingerprint,
    verify_report_data_binding,
    verify_report_data_binding_with_tls_fingerprint,
)
from .deployment_verifier import run_deployment_verifier
from .dstack_attestation import verify_dstack_deployment, verify_dstack_quote


async def verify_gateway_attestation(
    attestation: GatewayAttestation,
    client_binding: GatewayClientBinding,
    *,
    policy: AttestationPolicy | None = None,
    verifiers: AttestationVerifiers | None = None,
) -> VerifiedGatewayAttestation:
    """Verify Gateway evidence and its quote-bound TLS identity when present."""

    verified_quote = await verify_dstack_quote(
        attestation=attestation,
        advertised_report_data=attestation.reported_quote_data,
        nonce=client_binding.nonce,
        policy=policy,
        tdx_quote_verifier=None if verifiers is None else verifiers.tdx_quote,
    )
    if attestation.spki_fingerprint is not None:
        peer_spki_fingerprint = client_binding.spki_fingerprint
        if peer_spki_fingerprint is None:
            raise verification_failure('binding.spki_fingerprint_required')
        spki_fingerprint = verify_report_data_binding_with_tls_fingerprint(
            report_data=verified_quote.quote.report_data,
            nonce=client_binding.nonce,
            signer=verified_quote.signer,
            reported_spki_fingerprint=attestation.spki_fingerprint,
        )
        verify_peer_spki_fingerprint(spki_fingerprint, peer_spki_fingerprint)
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
    deployment = await verify_dstack_deployment(verified_quote)
    provenance = await run_deployment_verifier(
        deployment, None if verifiers is None else verifiers.deployment
    )
    return VerifiedGatewayAttestation(
        signer=verified_quote.signer,
        tcb_status=verified_quote.quote.tcb_status,
        advisory_ids=tuple(verified_quote.quote.advisory_ids),
        deployment=deployment,
        deployment_provenance=provenance,
        tls_binding=tls_binding,
    )
