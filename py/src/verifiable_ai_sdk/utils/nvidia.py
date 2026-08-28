"""Default NVIDIA NRAS evidence adapter."""

from __future__ import annotations

import base64
import json

import aiohttp
from pydantic import ValidationError

from ..schemas import (
    _NrasJwtPayloadSchema,
    _NrasOverallAttestationJwtClaimsSchema,
    _NrasResponseSchema,
)
from .consts import NVIDIA_GPU_VERIFIER_API_URL, TIMEOUT
from .errors import verification_failure
from .fetch import FetchResponse, fetch


async def verify_nvidia_nras(nvidia_payload: str) -> None:
    """Verify the documented boolean NRAS overall verdict over HTTPS.

    This adapter deliberately does not independently verify the returned JWT
    signature. Applications that need local JWT/EAT verification can pass a
    custom NVIDIA verifier to ``verify_model_attestation``.
    """

    try:
        response = await fetch(
            NVIDIA_GPU_VERIFIER_API_URL,
            method='POST',
            data=nvidia_payload,
            headers={'content-type': 'application/json'},
            timeout=TIMEOUT,
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
    jwt = _decode_nras_overall_attestation_jwt(raw)
    if _decode_nras_overall_attestation_verdict(jwt):
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


def _decode_nras_overall_attestation_verdict(jwt: str) -> bool:
    payload = _decode_nras_jwt_payload(jwt)
    try:
        return _NrasOverallAttestationJwtClaimsSchema.model_validate(
            payload
        ).overall_attestation_result
    except ValidationError:
        raise _invalid_nras_response('invalid_verdict_type') from None


def _decode_nras_jwt_payload(jwt: str) -> dict[str, object]:
    parts = jwt.split('.')
    if len(parts) != 3:
        raise _invalid_nras_response('invalid_jwt')

    encoded_payload = parts[1] + '=' * ((4 - len(parts[1]) % 4) % 4)
    try:
        value = json.loads(base64.urlsafe_b64decode(encoded_payload))
    except (UnicodeDecodeError, ValueError) as error:
        raise _invalid_nras_response('invalid_jwt', error) from error
    try:
        return _NrasJwtPayloadSchema.model_validate(value).root
    except ValidationError as error:
        raise _invalid_nras_response('invalid_jwt', error) from error


def _invalid_nras_response(reason: str, cause: BaseException | None = None):
    return verification_failure(
        'gpu.nras_response_invalid', {'reason': reason}, cause=cause
    )
