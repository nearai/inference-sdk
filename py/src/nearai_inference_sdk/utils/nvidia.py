"""Default NVIDIA NRAS evidence adapter."""

from __future__ import annotations

import json

import aiohttp
import jwt
from pydantic import ValidationError

from ..schemas import (
    NvidiaPayloadNonceSchema,
    _NrasOverallAttestationJwtClaimsSchema,
    _NrasResponseSchema,
    _NvidiaJwksSchema,
)
from ..types.verification import NvidiaEvidenceVerifier
from .common import require_byte_length
from .consts import NVIDIA_GPU_VERIFIER_API_URL
from .errors import verification_failure
from .fetch import FetchResponse, fetch

NVIDIA_ISSUER = 'https://nras.attestation.nvidia.com'
NVIDIA_JWKS_URL = f'{NVIDIA_ISSUER}/.well-known/jwks.json'


def create_nvidia_evidence_verifier(
    nras_url: str = NVIDIA_GPU_VERIFIER_API_URL,
    jwks_url: str = NVIDIA_JWKS_URL,
) -> NvidiaEvidenceVerifier:
    """Create the NVIDIA verifier with NRAS and signing-key URLs.

    The issuer remains NVIDIA. The JWKS endpoint supplies trusted signing keys;
    configure only a trusted source. The returned verifier binds the signed
    verdict to the payload nonce; callers must bind that nonce to their request,
    as verify_model_attestation does.
    """

    async def verify_evidence(payload: str) -> None:
        nonce = decode_nvidia_payload_nonce(payload)
        await verify_nvidia_nras(payload, nonce, nras_url, jwks_url)

    return verify_evidence


def decode_nvidia_payload_nonce(payload: str) -> str:
    """Decode GPU evidence and require a 32-byte hexadecimal nonce."""

    try:
        parsed = NvidiaPayloadNonceSchema.model_validate_json(payload)
    except ValidationError as error:
        reason = (
            'invalid_json'
            if error.errors(include_url=False)[0]['type'] == 'json_invalid'
            else 'nonce_missing'
        )
        raise verification_failure(
            'gpu.payload_invalid', {'reason': reason}, cause=error
        ) from error
    require_byte_length(parsed.nonce, 32, 'nvidia_payload.nonce')
    return parsed.nonce


async def verify_nvidia_nras(
    nvidia_payload: str,
    nonce: str,
    nras_url: str = NVIDIA_GPU_VERIFIER_API_URL,
    jwks_url: str = NVIDIA_JWKS_URL,
) -> None:
    """Verify NRAS's ES384-signed overall verdict, issuer, time and nonce.

    Detached device claims are not consumed by this adapter.
    """

    try:
        response = await fetch(
            nras_url,
            method='POST',
            data=nvidia_payload,
            headers={'content-type': 'application/json'},
        )
    except (aiohttp.ClientError, TimeoutError, OSError) as error:
        raise verification_failure(
            'gpu.nras_request_failed',
            {'reason': 'transport'},
            retryable=True,
            cause=error,
        ) from error

    if not response.ok:
        raise verification_failure(
            'gpu.nras_request_failed',
            {'reason': 'http_status', 'status': response.status},
            retryable=response.status in {408, 429} or response.status >= 500,
        )

    raw = _decode_nras_json(response)
    token = _decode_nras_overall_attestation_jwt(raw)
    key_set = await _fetch_nvidia_jwks(jwks_url)
    claims = _verify_nras_jwt(token, key_set)
    if bytes.fromhex(claims.eat_nonce) != bytes.fromhex(
        nonce.removeprefix('0x').removeprefix('0X')
    ):
        raise _jwt_failure('nonce_mismatch')
    if claims.overall_attestation_result:
        return
    raise verification_failure('gpu.attestation_rejected', {'source': 'nras'})


def _decode_nras_json(response: FetchResponse) -> object:
    try:
        return json.loads(response.text())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _invalid_nras_response('invalid_json', error) from error


def _decode_nras_overall_attestation_jwt(value: object) -> str:
    try:
        return _NrasResponseSchema.model_validate(value).overall_attestation_jwt
    except ValidationError as error:
        raise _invalid_nras_response('invalid_schema', error) from error


async def _fetch_nvidia_jwks(jwks_url: str) -> jwt.PyJWKSet:
    try:
        response = await fetch(jwks_url)
    except (aiohttp.ClientError, TimeoutError, OSError) as error:
        raise verification_failure(
            'gpu.jwks_request_failed',
            {'reason': 'transport'},
            retryable=True,
            cause=error,
        ) from error
    if not response.ok:
        raise verification_failure(
            'gpu.jwks_request_failed',
            {'reason': 'http_status', 'status': response.status},
            retryable=response.status in {408, 429} or response.status >= 500,
        )
    try:
        key_set = _NvidiaJwksSchema.model_validate_json(response.text())
        return jwt.PyJWKSet.from_dict(key_set.model_dump())
    except (jwt.PyJWTError, ValueError, TypeError, KeyError) as error:
        raise _invalid_nras_response('invalid_jwks', error) from error


def _verify_nras_jwt(
    token: str, key_set: jwt.PyJWKSet
) -> _NrasOverallAttestationJwtClaimsSchema:
    try:
        header = jwt.get_unverified_header(token)
        if header.get('alg') != 'ES384':
            raise _jwt_failure('unsupported_algorithm')
        kid = header.get('kid')
        if not isinstance(kid, str):
            raise _jwt_failure('key_not_found')
        try:
            key = key_set[kid]
        except KeyError as error:
            raise _jwt_failure('key_not_found', error) from error
        value = jwt.decode(
            token,
            key.key,
            algorithms=['ES384'],
            issuer=NVIDIA_ISSUER,
            options={'require': ['exp', 'nbf', 'iat'], 'verify_aud': False},
        )
        return _NrasOverallAttestationJwtClaimsSchema.model_validate(value)
    except jwt.ExpiredSignatureError as error:
        raise _jwt_failure('expired', error) from error
    except jwt.ImmatureSignatureError as error:
        raise _jwt_failure('not_yet_valid', error) from error
    except jwt.InvalidSignatureError as error:
        raise _jwt_failure('invalid_signature', error) from error
    except jwt.InvalidAlgorithmError as error:
        raise _jwt_failure('unsupported_algorithm', error) from error
    except jwt.InvalidTokenError as error:
        raise _jwt_failure('invalid_claims', error) from error
    except jwt.PyJWTError as error:
        raise _jwt_failure('invalid_signature', error) from error
    except (ValidationError, TypeError) as error:
        raise _jwt_failure('invalid_claims', error) from error


def _jwt_failure(reason: str, cause: BaseException | None = None):
    return verification_failure(
        'gpu.jwt_verification_failed', {'reason': reason}, cause=cause
    )


def _invalid_nras_response(reason: str, cause: BaseException | None = None):
    return verification_failure(
        'gpu.nras_response_invalid', {'reason': reason}, cause=cause
    )
