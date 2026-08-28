from __future__ import annotations

import hashlib

import nacl.signing
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from verifiable_ai_sdk import (
    CompletionSignature,
    ModelAttestationVerifiers,
    SigningIdentity,
    VerificationError,
    verify_gateway_attestation,
    verify_gateway_response,
    verify_model_attestation,
    verify_model_response,
)

from .fixtures import (
    NONCE,
    TLS_FINGERPRINT,
    create_gateway_attestation,
    create_model_attestation,
    create_quote,
)


REQUEST_BODY = b'{"model":"canonical-model"}'
RESPONSE_BODY = b'data: hello\n\n'


def model_signed_text(model: str, request: bytes, response: bytes) -> str:
    return f'{model}:{hashlib.sha256(request).hexdigest()}:{hashlib.sha256(response).hexdigest()}'


def gateway_signed_text(request: bytes, response: bytes) -> str:
    return (
        f'{hashlib.sha256(request).hexdigest()}:{hashlib.sha256(response).hexdigest()}'
    )


async def test_model_response_accepts_equivalent_signer_hex() -> None:
    account = Account.from_key(
        '0x0123456789012345678901234567890123456789012345678901234567890123'
    )
    signed_text = model_signed_text('canonical-model', REQUEST_BODY, RESPONSE_BODY)
    signature = CompletionSignature(
        kind='provider_tee',
        signed_text=signed_text,
        signature=account.sign_message(
            encode_defunct(text=signed_text)
        ).signature.hex(),
        signer=SigningIdentity(
            signing_algo='ecdsa',
            signing_address=f'0X{account.address[2:].upper()}',
        ),
    )
    quote = create_quote(signing_address=account.address)
    attestation = await verify_model_attestation(
        create_model_attestation(
            signer=SigningIdentity(
                signing_algo='ecdsa', signing_address=account.address
            )
        ),
        NONCE,
        verifiers=ModelAttestationVerifiers(quote=lambda _: quote),
    )

    verify_model_response(
        REQUEST_BODY,
        RESPONSE_BODY,
        signature,
        attestation,
    )

    with pytest.raises(VerificationError) as mismatch:
        verify_model_response(
            b'{"model":"alias"}',
            RESPONSE_BODY,
            signature,
            attestation,
        )
    assert mismatch.value.failure.code == 'signature.payload_mismatch'


async def test_gateway_response_verifies_ed25519_signature() -> None:
    key_pair = nacl.signing.SigningKey(bytes([7]) * 32)
    public_key = key_pair.verify_key.encode().hex()
    signed_text = gateway_signed_text(REQUEST_BODY, RESPONSE_BODY)
    signature = CompletionSignature(
        kind='gateway',
        signed_text=signed_text,
        signature=key_pair.sign(signed_text.encode()).signature.hex(),
        signer=SigningIdentity(signing_algo='ed25519', signing_address=public_key),
    )
    quote = create_quote(signing_address=public_key)
    attestation = await verify_gateway_attestation(
        create_gateway_attestation(
            signer=SigningIdentity(signing_algo='ed25519', signing_address=public_key),
            reported_quote_data=quote.report_data.hex(),
        ),
        NONCE,
        TLS_FINGERPRINT,
        verifiers=ModelAttestationVerifiers(quote=lambda _: quote),
    )

    verify_gateway_response(
        REQUEST_BODY,
        RESPONSE_BODY,
        signature,
        attestation,
    )


async def test_response_verifier_rejects_the_other_signature_kind() -> None:
    signature = CompletionSignature(
        kind='gateway',
        signed_text='request:response',
        signature='aa',
        signer=SigningIdentity(signing_algo='ecdsa', signing_address='11' * 20),
    )
    attestation = await verify_model_attestation(
        create_model_attestation(
            signer=SigningIdentity(signing_algo='ecdsa', signing_address='11' * 20)
        ),
        NONCE,
        verifiers=ModelAttestationVerifiers(
            quote=lambda _: create_quote(signing_address='11' * 20)
        ),
    )

    with pytest.raises(VerificationError) as raised:
        verify_model_response(
            REQUEST_BODY,
            RESPONSE_BODY,
            signature,
            attestation,
        )
    assert raised.value.failure.code == 'signature.kind_mismatch'
