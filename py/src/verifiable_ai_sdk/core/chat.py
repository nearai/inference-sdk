"""Exact-byte completion signature verification."""

from __future__ import annotations

import hashlib

import nacl.exceptions
import nacl.signing
from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import ValidationError

from ..schemas import CompletionRequestModelSchema
from ..types.attestation_common import SigningAlgo, SigningIdentity
from ..types.chat import CompletionSignature, CompletionSignatureKind
from ..types.verification import (
    VerifiedGatewayAttestation,
    VerifiedModelAttestation,
)
from ..utils.common import hex_to_bytes
from ..utils.errors import VerificationError, verification_failure


def verify_model_response(
    request_body: bytes,
    response_body: bytes,
    signature: CompletionSignature,
    attestation: VerifiedModelAttestation,
) -> None:
    """Verify a provider TEE signature over exact request and response bytes."""

    _require_kind(signature, 'provider_tee')
    model = _model_from_request(request_body)
    expected = _model_signature_text(model, request_body, response_body)
    _verify_signature_text_and_bytes(signature, expected)
    _verify_signature_matches_attestation(signature, attestation.signer)


def verify_gateway_response(
    request_body: bytes,
    response_body: bytes,
    signature: CompletionSignature,
    attestation: VerifiedGatewayAttestation,
) -> None:
    """Verify a Gateway signature over exact client-visible request/response bytes."""

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


def _require_kind(
    signature: CompletionSignature, expected: CompletionSignatureKind
) -> None:
    if signature.kind != expected:
        raise verification_failure(
            'signature.kind_mismatch',
            {'expected': expected, 'actual': signature.kind},
        )


def _model_from_request(request_body: bytes) -> str:
    try:
        return CompletionRequestModelSchema.model_validate_json(request_body).model
    except ValidationError as error:
        reason = (
            'invalid_json'
            if error.errors(include_url=False)[0]['type'] == 'json_invalid'
            else 'missing_model'
        )
        raise verification_failure(
            'signature.payload_mismatch',
            {'source': 'request_model', 'reason': reason},
            cause=error,
        ) from error


def _verify_signature_text_and_bytes(
    signature: CompletionSignature, expected_text: str
) -> None:
    if signature.signed_text != expected_text:
        raise verification_failure(
            'signature.payload_mismatch',
            {'source': 'signed_payload', 'reason': 'text_mismatch'},
        )
    _verify_signature_bytes(signature)


def _verify_signature_matches_attestation(
    signature: CompletionSignature, attestation_signer: SigningIdentity
) -> None:
    signature_signer = signature.signer
    signature_algo = _require_signing_algo(
        signature_signer.signing_algo,
        'signature.signer.signing_algo',
    )
    attestation_algo = _require_signing_algo(
        attestation_signer.signing_algo,
        'attestation.signer.signing_algo',
    )
    signer_matches = signature_algo == attestation_algo and hex_to_bytes(
        signature_signer.signing_address,
        'signature.signer.signing_address',
    ) == hex_to_bytes(
        attestation_signer.signing_address,
        'attestation.signer.signing_address',
    )
    if not signer_matches:
        raise verification_failure('signature.signer_mismatch')


def _verify_signature_bytes(signature: CompletionSignature) -> None:
    signer = signature.signer
    signed_text = signature.signed_text
    algorithm = _require_signing_algo(
        signer.signing_algo, 'signature.signer.signing_algo'
    )
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


def _require_signing_algo(value: object, field: str) -> SigningAlgo:
    if isinstance(value, str) and value in {'ecdsa', 'ed25519'}:
        return value
    raise verification_failure(
        'input.invalid',
        {
            'field': field,
            'reason': 'unsupported_value',
            'expected': "'ecdsa' or 'ed25519'",
        },
    )


def _parse_signature_hex(value: str, field: str) -> bytes:
    try:
        return hex_to_bytes(value, field)
    except VerificationError as error:
        raise verification_failure(
            'signature.format_invalid',
            {'field': field, 'reason': 'invalid_hex'},
            cause=error,
        ) from error


def _require_signature_length(field: str, value: bytes, length: int) -> None:
    if len(value) != length:
        raise verification_failure(
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
        'signature.invalid', {'signingAlgo': algorithm}, cause=cause
    )
