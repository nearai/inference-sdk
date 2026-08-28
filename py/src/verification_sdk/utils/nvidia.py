"""Default NVIDIA NRAS evidence adapter."""

from __future__ import annotations

import json

import aiohttp

from .common import decode_jwt
from .consts import NVIDIA_GPU_VERIFIER_API_URL, TIMEOUT
from .errors import verification_failure
from .fetch import fetch


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
            'gpu',
            'gpu.nras_request_failed',
            {'reason': 'transport'},
            retryable=True,
            cause=error,
        ) from error

    if not response.ok:
        raise verification_failure(
            'gpu',
            'gpu.nras_request_failed',
            {'reason': 'http_status', 'status': response.status},
            retryable=response.status in {408, 429} or response.status >= 500,
        )

    try:
        raw = json.loads(response.text())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _invalid_nras_response('invalid_json', error) from error

    try:
        first = raw[0]
        if not isinstance(first, list) or len(first) != 2 or first[0] != 'JWT':
            raise ValueError('missing overall JWT')
        jwt = first[1]
        if not isinstance(jwt, str):
            raise ValueError('overall JWT is not text')
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise _invalid_nras_response('invalid_schema', error) from error

    try:
        claims = decode_jwt(jwt)
    except ValueError as error:
        raise _invalid_nras_response('invalid_jwt', error) from error

    verdict = claims.get('x-nvidia-overall-att-result')
    if verdict is True:
        return
    if verdict is False:
        raise verification_failure(
            'gpu', 'gpu.attestation_rejected', {'source': 'nras'}
        )
    raise _invalid_nras_response('invalid_verdict_type')


def _invalid_nras_response(reason: str, cause: BaseException | None = None):
    return verification_failure(
        'gpu', 'gpu.nras_response_invalid', {'reason': reason}, cause=cause
    )
