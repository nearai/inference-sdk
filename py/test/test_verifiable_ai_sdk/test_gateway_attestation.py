from __future__ import annotations

import pytest

from verifiable_ai_sdk import (
    AttestationVerifiers,
    VerificationError,
    verify_gateway_attestation,
)

from .fixtures import NONCE, TLS_FINGERPRINT, create_gateway_attestation, create_quote


async def test_gateway_attestation_binds_the_observed_tls_peer() -> None:
    result = await verify_gateway_attestation(
        create_gateway_attestation(),
        NONCE,
        TLS_FINGERPRINT,
        verifiers=AttestationVerifiers(quote=lambda _: create_quote()),
    )
    assert result.tls_binding.kind == 'peer'
    assert result.tls_binding.spki_fingerprint == TLS_FINGERPRINT

    with pytest.raises(VerificationError) as mismatch:
        await verify_gateway_attestation(
            create_gateway_attestation(),
            NONCE,
            '44' * 32,
            verifiers=AttestationVerifiers(quote=lambda _: create_quote()),
        )
    assert mismatch.value.failure.code == 'binding.spki_fingerprint_mismatch'

    with pytest.raises(VerificationError) as missing:
        await verify_gateway_attestation(
            create_gateway_attestation(declared_spki_fingerprint=None),
            NONCE,
            TLS_FINGERPRINT,
            verifiers=AttestationVerifiers(quote=lambda _: create_quote()),
        )
    assert missing.value.failure.code == 'binding.spki_fingerprint_missing'
