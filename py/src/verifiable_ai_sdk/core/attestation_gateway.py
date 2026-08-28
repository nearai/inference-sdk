"""NEAR AI Cloud Gateway attestation verification."""

from __future__ import annotations

from ..types.attestation_gateway import GatewayAttestation
from ..types.verification import (
    AttestationVerifiers,
    GatewayAttestationPolicy,
    GatewayClientBinding,
    VerifiedGatewayAttestation,
)
from ..utils.errors import verification_failure
from .attestation_common import verify_gateway_report_data_binding
from .dstack_attestation import verify_dstack_deployment, verify_dstack_quote


async def verify_gateway_attestation(
    attestation: GatewayAttestation,
    client_binding: GatewayClientBinding,
    *,
    policy: GatewayAttestationPolicy | None = None,
    verifiers: AttestationVerifiers | None = None,
) -> VerifiedGatewayAttestation:
    """Verify Gateway evidence and its quote-bound TLS identity.

    Peer TLS binding is required by default. Set
    ``verify_peer_tls_binding=False`` only when the runtime cannot observe the
    certificate for the evidence request.
    """

    verify_peer_tls_binding = True if policy is None else policy.verify_peer_tls_binding
    if verify_peer_tls_binding and client_binding.peer_spki_fingerprint is None:
        raise verification_failure('policy.peer_tls_binding_required')

    verified_quote = await verify_dstack_quote(
        attestation=attestation,
        advertised_report_data=attestation.reported_quote_data,
        nonce=client_binding.nonce,
        policy=policy,
        quote_verifier=None if verifiers is None else verifiers.quote,
    )
    tls_binding = verify_gateway_report_data_binding(
        report_data=verified_quote.quote.report_data,
        nonce=client_binding.nonce,
        signer=verified_quote.signer,
        reported_spki_fingerprint=attestation.declared_spki_fingerprint,
        peer_spki_fingerprint=(
            client_binding.peer_spki_fingerprint if verify_peer_tls_binding else None
        ),
    )
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
