"""NEAR AI Cloud Gateway attestation verification."""

from __future__ import annotations

from ..types.attestation_gateway import GatewayAttestation
from ..types.verification import (
    AttestationPolicy,
    AttestationVerifiers,
    VerifiedGatewayAttestation,
    VerifyGatewayAttestationInput,
)
from ..utils.common import require_instance
from .attestation_common import verify_gateway_report_data_binding
from .dstack_attestation import verify_dstack_deployment, verify_dstack_quote


async def verify_gateway_attestation(
    input: VerifyGatewayAttestationInput,
) -> VerifiedGatewayAttestation:
    """Verify Gateway evidence and bind it to a caller-observed TLS peer."""

    input = require_instance(input, VerifyGatewayAttestationInput, 'input')
    attestation = require_instance(input.attestation, GatewayAttestation, 'attestation')
    require_instance(
        attestation.reported_quote_data, str, 'attestation.reported_quote_data'
    )
    policy = (
        None
        if input.policy is None
        else require_instance(input.policy, AttestationPolicy, 'policy')
    )
    verifiers = (
        None
        if input.verifiers is None
        else require_instance(input.verifiers, AttestationVerifiers, 'verifiers')
    )
    verified_quote = await verify_dstack_quote(
        attestation=attestation,
        nonce=input.nonce,
        policy=policy,
        quote_verifier=None if verifiers is None else verifiers.quote,
    )
    tls_binding = verify_gateway_report_data_binding(
        report_data=verified_quote.quote.report_data,
        nonce=input.nonce,
        signer=verified_quote.signer,
        reported_spki_fingerprint=attestation.declared_spki_fingerprint,
        peer_spki_fingerprint=input.peer_spki_fingerprint,
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
