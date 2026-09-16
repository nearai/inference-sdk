from __future__ import annotations

import pytest

from nearai_inference_sdk import (
    AttestationPolicy,
    AttestationVerifiers,
    GatewayClientBinding,
    VerificationError,
    verify_gateway_attestation,
)

from .fixtures import (
    NONCE,
    TLS_FINGERPRINT,
    create_gateway_attestation,
    create_gateway_tls_quote,
    create_model_quote,
)


async def test_gateway_attestation_binds_the_observed_tls_peer() -> None:
    result = await verify_gateway_attestation(
        create_gateway_attestation(),
        GatewayClientBinding(
            nonce=NONCE,
            spki_fingerprint=TLS_FINGERPRINT,
        ),
        verifiers=AttestationVerifiers(quote=lambda _: create_gateway_tls_quote()),
    )
    assert result.tls_binding.kind == 'attested'
    assert result.tls_binding.spki_fingerprint == TLS_FINGERPRINT


async def test_gateway_attestation_requires_a_peer_for_tls_bound_evidence() -> None:
    with pytest.raises(VerificationError) as missing_peer:
        await verify_gateway_attestation(
            create_gateway_attestation(),
            GatewayClientBinding(nonce=NONCE),
            verifiers=AttestationVerifiers(quote=lambda _: create_gateway_tls_quote()),
        )
    assert missing_peer.value.failure.code == 'binding.spki_fingerprint_required'


async def test_gateway_attestation_rejects_a_different_peer() -> None:
    with pytest.raises(VerificationError) as mismatch:
        await verify_gateway_attestation(
            create_gateway_attestation(),
            GatewayClientBinding(
                nonce=NONCE,
                spki_fingerprint='44' * 32,
            ),
            verifiers=AttestationVerifiers(quote=lambda _: create_gateway_tls_quote()),
        )
    assert mismatch.value.failure.code == 'binding.spki_fingerprint_mismatch'


async def test_gateway_attestation_uses_signer_nonce_binding_without_tls_fingerprint() -> (
    None
):
    quote = create_model_quote()
    result = await verify_gateway_attestation(
        create_gateway_attestation(
            spki_fingerprint=None,
            reported_quote_data=quote.report_data.hex(),
        ),
        GatewayClientBinding(nonce=NONCE),
        verifiers=AttestationVerifiers(quote=lambda _: quote),
    )

    assert result.tls_binding.kind == 'none'
    assert result.tls_binding.spki_fingerprint is None


async def test_gateway_attestation_honors_accepted_tcb_statuses() -> None:
    with pytest.raises(VerificationError) as rejected:
        await verify_gateway_attestation(
            create_gateway_attestation(),
            GatewayClientBinding(
                nonce=NONCE,
                spki_fingerprint=TLS_FINGERPRINT,
            ),
            policy=AttestationPolicy(accepted_tcb_statuses=('UpToDate',)),
            verifiers=AttestationVerifiers(
                quote=lambda _: create_gateway_tls_quote(tcb_status='OutOfDate')
            ),
        )

    assert rejected.value.failure.code == 'policy.tcb_status_not_allowed'


async def test_gateway_attestation_normalizes_a_rejected_deployment_verifier() -> None:
    async def reject(_) -> None:
        raise RuntimeError('deployment rejected')

    with pytest.raises(VerificationError) as rejected:
        await verify_gateway_attestation(
            create_gateway_attestation(),
            GatewayClientBinding(
                nonce=NONCE,
                spki_fingerprint=TLS_FINGERPRINT,
            ),
            verifiers=AttestationVerifiers(
                quote=lambda _: create_gateway_tls_quote(),
                deployment=reject,
            ),
        )

    assert rejected.value.failure.code == 'provenance.verification_failed'
