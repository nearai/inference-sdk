from __future__ import annotations

import pytest

from verifiable_ai_sdk import (
    AttestationVerifiers,
    GatewayAttestationPolicy,
    GatewayClientBinding,
    VerificationError,
    verify_gateway_attestation,
)

from .fixtures import NONCE, TLS_FINGERPRINT, create_gateway_attestation, create_quote


async def test_gateway_attestation_binds_the_observed_tls_peer() -> None:
    result = await verify_gateway_attestation(
        create_gateway_attestation(),
        GatewayClientBinding(
            nonce=NONCE,
            peer_spki_fingerprint=TLS_FINGERPRINT,
        ),
        verifiers=AttestationVerifiers(quote=lambda _: create_quote()),
    )
    assert result.tls_binding.kind == 'peer'
    assert result.tls_binding.spki_fingerprint == TLS_FINGERPRINT


async def test_gateway_attestation_requires_a_peer_by_default() -> None:
    with pytest.raises(VerificationError) as missing_peer:
        await verify_gateway_attestation(
            create_gateway_attestation(),
            GatewayClientBinding(nonce=NONCE),
            verifiers=AttestationVerifiers(quote=lambda _: create_quote()),
        )
    assert missing_peer.value.failure.code == 'policy.peer_tls_binding_required'


async def test_gateway_attestation_rejects_a_different_peer() -> None:
    with pytest.raises(VerificationError) as mismatch:
        await verify_gateway_attestation(
            create_gateway_attestation(),
            GatewayClientBinding(
                nonce=NONCE,
                peer_spki_fingerprint='44' * 32,
            ),
            verifiers=AttestationVerifiers(quote=lambda _: create_quote()),
        )
    assert mismatch.value.failure.code == 'binding.spki_fingerprint_mismatch'


async def test_gateway_attestation_can_skip_peer_tls_binding_explicitly() -> None:
    result = await verify_gateway_attestation(
        create_gateway_attestation(),
        GatewayClientBinding(
            nonce=NONCE,
            peer_spki_fingerprint='not-a-fingerprint',
        ),
        policy=GatewayAttestationPolicy(verify_peer_tls_binding=False),
        verifiers=AttestationVerifiers(quote=lambda _: create_quote()),
    )

    assert result.tls_binding.kind == 'attested'
    assert result.tls_binding.spki_fingerprint == TLS_FINGERPRINT
