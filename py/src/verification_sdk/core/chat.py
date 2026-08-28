"""Exact-byte completion signature verification."""

from __future__ import annotations

import hashlib
import json

import nacl.exceptions
import nacl.signing
from eth_account import Account
from eth_account.messages import encode_defunct

from ..types.attestation_common import SigningIdentity
from ..types.chat import CompletionSignature
from ..types.verification import (
    VerifiedGatewayAttestation,
    VerifiedModelAttestation,
    VerifyGatewayResponseInput,
    VerifyModelResponseInput,
)
from ..utils.common import hex_to_bytes, normalize_hex, require_instance
from ..utils.errors import VerificationError, verification_failure


def verify_model_response(input: VerifyModelResponseInput) -> None:
    """Verify a provider TEE signature over exact request and response bytes."""

    input = require_instance(input, VerifyModelResponseInput, 'input')
    request_body = require_instance(input.request_body, bytes, 'request_body')
    response_body = require_instance(input.response_body, bytes, 'response_body')
    signature = require_instance(input.signature, CompletionSignature, 'signature')
    attestation = require_instance(
        input.attestation, VerifiedModelAttestation, 'attestation'
    )
    _require_kind(signature, 'provider_tee')
    model = _model_from_request(request_body)
    expected = _model_signature_text(model, request_body, response_body)
    _verify_signature_text_and_bytes(signature, expected)
    _verify_signature_matches_attestation(signature, attestation.signer)


def verify_gateway_response(input: VerifyGatewayResponseInput) -> None:
    """Verify a Gateway signature over exact client-visible request/response bytes."""

    input = require_instance(input, VerifyGatewayResponseInput, 'input')
    request_body = require_instance(input.request_body, bytes, 'request_body')
    response_body = require_instance(input.response_body, bytes, 'response_body')
    signature = require_instance(input.signature, CompletionSignature, 'signature')
    attestation = require_instance(
        input.attestation, VerifiedGatewayAttestation, 'attestation'
    )
    _require_kind(signature, 'gateway')
    expected = _gateway_signature_text(request_body, response_body)
    _verify_signature_text_and_bytes(signature, expected)
    _verify_signature_matches_attestation(signature, attestation.signer)


def _model_signature_text(model: str, request_body: bytes, response_body: bytes) -> str:
    return f'{model}:{_sha256_hex(request_body)}:{_sha256_hex(response_body)}'


def _gateway_signature_text(request_body: bytes, response_body: bytes) -> str:
    return f'{_sha256_hex(request_body)}:{_sha256_hex(response_body)}'


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_kind(signature: CompletionSignature, expected: str) -> None:
    if signature.kind != expected:
        raise verification_failure(
            'signature',
            'signature.kind_mismatch',
            {'expected': expected, 'actual': signature.kind},
        )


def _model_from_request(request_body: bytes) -> str:
    try:
        parsed = json.loads(request_body.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise verification_failure(
            'signature',
            'signature.payload_mismatch',
            {'source': 'request_model', 'reason': 'invalid_json'},
            cause=error,
        ) from error
    if not isinstance(parsed, dict) or not isinstance(parsed.get('model'), str):
        raise verification_failure(
            'signature',
            'signature.payload_mismatch',
            {'source': 'request_model', 'reason': 'missing_model'},
        )
    model = parsed['model']
    if not model:
        raise verification_failure(
            'signature',
            'signature.payload_mismatch',
            {'source': 'request_model', 'reason': 'missing_model'},
        )
    return model


def _verify_signature_text_and_bytes(
    signature: CompletionSignature, expected_text: str
) -> None:
    if signature.signed_text != expected_text:
        raise verification_failure(
            'signature',
            'signature.payload_mismatch',
            {'source': 'signed_payload', 'reason': 'text_mismatch'},
        )
    _verify_signature_bytes(signature)


def _verify_signature_matches_attestation(
    signature: CompletionSignature, attestation_signer: SigningIdentity
) -> None:
    signature_signer = require_instance(
        signature.signer, SigningIdentity, 'signature.signer'
    )
    attestation_signer = require_instance(
        attestation_signer, SigningIdentity, 'attestation.signer'
    )
    try:
        signer_matches = (
            signature_signer.signing_algo == attestation_signer.signing_algo
            and normalize_hex(signature_signer.signing_address)
            == normalize_hex(attestation_signer.signing_address)
        )
    except VerificationError as error:
        raise verification_failure(
            'signature', 'signature.signer_mismatch', cause=error
        ) from error
    if not signer_matches:
        raise verification_failure('signature', 'signature.signer_mismatch')


def _verify_signature_bytes(signature: CompletionSignature) -> None:
    signer = require_instance(signature.signer, SigningIdentity, 'signature.signer')
    signed_text = require_instance(signature.signed_text, str, 'signature.signed_text')
    algorithm = signer.signing_algo
    if algorithm == 'ecdsa':
        signature_bytes = _parse_signature_hex(signature.signature, 'signature')
        signing_address = _parse_signature_hex(
            signer.signing_address, 'signer.signing_address'
        )
        _require_signature_length('signature', signature_bytes, 65)
        _require_signature_length('signer.signing_address', signing_address, 20)
        try:
            recovered = Account.recover_message(
                encode_defunct(text=signature.signed_text),
                signature=signature.signature,
            )
        except Exception as error:
            raise _invalid_signature('ecdsa', error) from error
        if _parse_signature_hex(recovered, 'signer.signing_address') != signing_address:
            raise _invalid_signature('ecdsa')
        return

    if algorithm == 'ed25519':
        public_key = _parse_signature_hex(
            signer.signing_address, 'signer.signing_address'
        )
        signed = _parse_signature_hex(signature.signature, 'signature')
        _require_signature_length('signer.signing_address', public_key, 32)
        _require_signature_length('signature', signed, 64)
        try:
            nacl.signing.VerifyKey(public_key).verify(
                signed_text.encode('utf-8'), signed
            )
        except (nacl.exceptions.BadSignatureError, ValueError) as error:
            raise _invalid_signature('ed25519', error) from error
        return

    raise verification_failure(
        'signature',
        'signature.format_invalid',
        {
            'field': 'signer.signing_algo',
            'reason': 'unsupported_signing_algo',
        },
    )


def _parse_signature_hex(value: str, field: str) -> bytes:
    try:
        return hex_to_bytes(value, field)
    except VerificationError as error:
        raise verification_failure(
            'signature',
            'signature.format_invalid',
            {'field': field, 'reason': 'invalid_hex'},
            cause=error,
        ) from error


def _require_signature_length(field: str, value: bytes, length: int) -> None:
    if len(value) != length:
        raise verification_failure(
            'signature',
            'signature.format_invalid',
            {
                'field': field,
                'reason': 'wrong_length',
                'expectedBytes': length,
                'actualBytes': len(value),
            },
        )


def _invalid_signature(algorithm: str, cause: BaseException | None = None):
    return verification_failure(
        'signature', 'signature.invalid', {'signingAlgo': algorithm}, cause=cause
    )
