"""Bind advertised OHTTP keys to the verified Gateway signing identity."""

from dataclasses import replace

import pytest
from nacl.signing import SigningKey

from nearai_inference_sdk import (
    OhttpAttestation,
    SigningIdentity,
    VerificationError,
    verify_ohttp_key_config,
)


SIGNING_KEY = SigningKey(bytes([7]) * 32)
KEY_CONFIG = bytes.fromhex('010020' + '33' * 32 + '000400010001')
SIGNER = SigningIdentity(
    signing_algo='ed25519', signing_address=bytes(SIGNING_KEY.verify_key).hex()
)
PROOF = OhttpAttestation(
    signing_algo='ed25519',
    signing_key=SIGNER.signing_address,
    key_config=KEY_CONFIG.hex(),
    signature=SIGNING_KEY.sign(KEY_CONFIG).signature.hex(),
)


def test_returns_signed_raw_configuration_with_equivalent_hex_formats() -> None:
    proof = replace(
        PROOF,
        signing_key=PROOF.signing_key.upper(),
        key_config=f'0X{PROOF.key_config.upper()}',
        signature=f'0x{PROOF.signature}',
    )

    assert (
        verify_ohttp_key_config(
            proof, replace(SIGNER, signing_address=f'0x{SIGNER.signing_address}')
        )
        == KEY_CONFIG
    )


@pytest.mark.parametrize(
    'signer',
    [
        SigningIdentity(signing_algo='ecdsa', signing_address='11' * 20),
        SigningIdentity(signing_algo='ed25519', signing_address='11' * 32),
    ],
)
def test_rejects_an_unauthenticated_signer_before_parsing_configuration(
    signer: SigningIdentity,
) -> None:
    with pytest.raises(VerificationError) as raised:
        verify_ohttp_key_config(replace(PROOF, key_config='not-hex'), signer)

    assert raised.value.failure.code == 'ohttp.signer_mismatch'


@pytest.mark.parametrize(
    'proof',
    [
        replace(PROOF, key_config=f'02{PROOF.key_config[2:]}'),
        replace(PROOF, signature='00' * 64),
        replace(PROOF, signature='00' * 63),
        replace(
            PROOF,
            signature=SIGNING_KEY.sign(PROOF.key_config.encode()).signature.hex(),
        ),
    ],
)
def test_rejects_modified_evidence_and_signatures_over_hex_text(
    proof: OhttpAttestation,
) -> None:
    with pytest.raises(VerificationError) as raised:
        verify_ohttp_key_config(proof, SIGNER)

    assert raised.value.failure.code == 'ohttp.signature_invalid'
    assert raised.value.retryable is False


@pytest.mark.parametrize('field', ['signing_key', 'key_config', 'signature'])
def test_reports_malformed_manual_proof_as_input_error(field: str) -> None:
    with pytest.raises(VerificationError) as raised:
        verify_ohttp_key_config(replace(PROOF, **{field: 'not-hex'}), SIGNER)

    assert raised.value.failure.code == 'input.invalid'
    assert raised.value.failure.details == {
        'field': f'ohttp_attestation.{field}',
        'reason': 'invalid_hex',
    }
