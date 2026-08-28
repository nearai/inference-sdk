"""NEAR AI Cloud Gateway attestation verification."""

from __future__ import annotations

from ..types.attestation_gateway import GatewayAttestation
from ..types.verification import (
    AttestationPolicy,
    AttestationVerifiers,
    VerifiedGatewayAttestation,
)
from .attestation_common import verify_gateway_report_data_binding
from .dstack_attestation import verify_dstack_deployment, verify_dstack_quote


async def verify_gateway_attestation(
    attestation: GatewayAttestation,
    nonce: str,
    peer_spki_fingerprint: str,
    *,
    policy: AttestationPolicy | None = None,
    verifiers: AttestationVerifiers | None = None,
) -> VerifiedGatewayAttestation:
    """Verify Gateway evidence and bind it to a caller-observed TLS peer."""

    verified_quote = await verify_dstack_quote(
        attestation=attestation,
        advertised_report_data=attestation.reported_quote_data,
        nonce=nonce,
        policy=policy,
        quote_verifier=None if verifiers is None else verifiers.quote,
    )
    tls_binding = verify_gateway_report_data_binding(
        report_data=verified_quote.quote.report_data,
        nonce=nonce,
        signer=verified_quote.signer,
        reported_spki_fingerprint=attestation.declared_spki_fingerprint,
        peer_spki_fingerprint=peer_spki_fingerprint,
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
