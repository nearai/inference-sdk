from __future__ import annotations

import hashlib
from dataclasses import replace

import nacl.signing
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from nearai_inference_sdk import (
    AttestationVerifiers,
    CompletionSignature,
    GatewayClientBinding,
    ModelAttestationVerifiers,
    SigningIdentity,
    VerificationError,
    verify_gateway_attestation,
    verify_gateway_response,
    verify_model_attestation,
    verify_model_response,
)

from .fixtures import (
    MODEL_CLIENT_BINDING,
    NONCE,
    TLS_FINGERPRINT,
    create_gateway_attestation,
    create_gateway_tls_quote,
    create_model_attestation,
    create_model_quote,
)

REQUEST_BODY = b'{"model":"canonical-model"}'
RESPONSE_BODY = b'data: hello\n\n'


@pytest.fixture(params=['ed25519', 'ecdsa'])
def signing_key(request):
    if request.param == 'ed25519':
        key = nacl.signing.SigningKey(bytes([7]) * 32)
        address = key.verify_key.encode().hex()

        def sign(text):
            return key.sign(text.encode()).signature.hex()

    else:
        key = Account.from_key(bytes([7]) * 32)
        address = key.address

        def sign(text):
            return key.sign_message(encode_defunct(text=text)).signature.hex()

    return SigningIdentity(signing_algo=request.param, signing_address=address), sign


@pytest.fixture(params=['provider_tee', 'gateway'])
async def signed_response(request, signing_key):
    signer, sign = signing_key
    text = f'{hashlib.sha256(REQUEST_BODY).hexdigest()}:{hashlib.sha256(RESPONSE_BODY).hexdigest()}'
    if request.param == 'provider_tee':
        text = f'canonical-model:{text}'
        quote = create_model_quote(signing_address=signer.signing_address)
        attestation = await verify_model_attestation(
            create_model_attestation(signer=signer),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(tdx_quote=lambda _: quote),
        )
        verify = verify_model_response
    else:
        quote = create_gateway_tls_quote(signing_address=signer.signing_address)
        attestation = await verify_gateway_attestation(
            create_gateway_attestation(
                signer=signer, reported_quote_data=quote.report_data.hex()
            ),
            GatewayClientBinding(nonce=NONCE, spki_fingerprint=TLS_FINGERPRINT),
            verifiers=AttestationVerifiers(tdx_quote=lambda _: quote),
        )
        verify = verify_gateway_response
    signature = CompletionSignature(
        kind=request.param, signed_text=text, signature=sign(text), signer=signer
    )
    return verify, signature, attestation


async def test_response_verifies_exact_bytes_and_equivalent_signer_hex(signed_response):
    verify, signature, attestation = signed_response
    verify(REQUEST_BODY, RESPONSE_BODY, signature, attestation)
    normalized = replace(
        signature,
        signer=replace(
            signature.signer,
            signing_address='0X'
            + signature.signer.signing_address.removeprefix('0x').upper(),
        ),
    )
    verify(REQUEST_BODY, RESPONSE_BODY, normalized, attestation)


@pytest.mark.parametrize(
    ('tamper', 'code'),
    [
        ('request-bytes', 'signature.payload_mismatch'),
        ('request-model', 'signature.payload_mismatch'),
        ('response-bytes', 'signature.payload_mismatch'),
        ('signed-text', 'signature.payload_mismatch'),
        ('signature-bytes', 'signature.invalid'),
        ('different-signer', 'signature.signer_mismatch'),
        ('other-kind', 'signature.kind_mismatch'),
    ],
)
async def test_response_rejects_independent_tampering(signed_response, tamper, code):
    verify, signature, attestation = signed_response
    request_body, response_body = REQUEST_BODY, RESPONSE_BODY
    if tamper == 'request-bytes':
        request_body += b' '
    elif tamper == 'request-model':
        request_body = b'{"model":"alias"}'
    elif tamper == 'response-bytes':
        response_body += b' '
    elif tamper == 'signed-text':
        signature = replace(signature, signed_text=signature.signed_text + 'x')
    elif tamper == 'signature-bytes':
        mutated = bytearray.fromhex(signature.signature)
        mutated[0] ^= 1
        signature = replace(signature, signature=mutated.hex())
    elif tamper == 'different-signer':
        size = 32 if signature.signer.signing_algo == 'ed25519' else 20
        attestation = replace(
            attestation,
            signer=replace(attestation.signer, signing_address='11' * size),
        )
    else:
        signature = replace(
            signature,
            kind='gateway' if signature.kind == 'provider_tee' else 'provider_tee',
        )
    with pytest.raises(VerificationError) as raised:
        verify(request_body, response_body, signature, attestation)
    assert raised.value.failure.code == code


@pytest.mark.parametrize(
    ('request_body', 'reason'),
    [
        (b'{"model":""}', 'missing_model'),
        (b'{}', 'missing_model'),
        (b'{', 'invalid_json'),
    ],
)
async def test_model_response_requires_a_canonical_request_model(request_body, reason):
    signer = SigningIdentity(signing_algo='ecdsa', signing_address='11' * 20)
    attestation = await verify_model_attestation(
        create_model_attestation(signer=signer),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(
            tdx_quote=lambda _: create_model_quote(
                signing_address=signer.signing_address
            )
        ),
    )
    signature = CompletionSignature(
        kind='provider_tee', signed_text='', signature='', signer=signer
    )
    with pytest.raises(VerificationError) as raised:
        verify_model_response(request_body, RESPONSE_BODY, signature, attestation)
    assert raised.value.failure.code == 'signature.payload_mismatch'
    assert raised.value.failure.details == {'source': 'request_model', 'reason': reason}
