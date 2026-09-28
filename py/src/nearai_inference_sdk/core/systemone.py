"""Non-streaming decisions: one inference attempt, independently retryable receipt."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

import httpx
from pydantic import ValidationError

from ..schemas import SystemOneRequestSchema, SystemOneResponseSchema
from ..types.cloud_api import NO_ALIASING_HEADER
from ..types.inference_client import VerifiedCompletionResult
from ..types.systemone import SystemOneRequest, SystemOneResponse, SystemOneResult
from ..utils.errors import (
    ApiError,
    VerificationError,
    api_failure,
    verification_failure,
)
from .e2ee_request import remove_e2ee_headers

if TYPE_CHECKING:
    from .inference_client import InferenceClient


class InferenceSystemOne:
    def __init__(self, client: InferenceClient) -> None:
        self._client = client

    async def create(
        self, request: SystemOneRequest, *, headers: Mapping[str, str] | None = None
    ) -> SystemOneResult:
        """Send a decision request; verify with result.verify() before trusting answers."""

        client = self._client
        if client._e2ee or client._ohttp:
            raise _invalid_input('System One requires e2ee=False and ohttp=False')
        try:
            request_body = json.dumps(request, allow_nan=False).encode()
            parsed = SystemOneRequestSchema.model_validate_json(request_body)
        except (ValidationError, ValueError, TypeError):
            raise _invalid_input(
                'a System One request with model, state, and typed questions (no stream)'
            ) from None
        # Fresh preflight for each decision, without Chat model-key routing.
        session = await client._create_session(parsed.model, systemone=True)
        request_headers = client._request_headers(headers or {})
        remove_e2ee_headers(request_headers)
        for name in (
            'content-length',
            'content-encoding',
            'transfer-encoding',
            'trailer',
        ):
            request_headers.pop(name, None)
        request_headers.update(
            {
                NO_ALIASING_HEADER: 'true',
                'content-type': 'application/json',
                'accept': 'application/json',
            }
        )
        http_request = httpx.Request(
            'POST',
            httpx.URL(client.base_url).join('systemone'),
            headers=request_headers,
            content=request_body,
        )
        try:
            response = await session.http_client.send(http_request, stream=True)
        except (ApiError, VerificationError):
            raise
        except httpx.HTTPError as error:
            raise api_failure(
                'api.transport_failed',
                {'resource': 'completion', 'reason': 'request'},
                cause=error,
            ) from error
        try:
            if not response.is_success:
                # Do not retain error bodies, which can contain private state.
                raise api_failure(
                    'api.http_status',
                    {'resource': 'completion', 'status': response.status_code},
                )
            signature_id = response.headers.get('x-signature-id', '')
            if re.fullmatch(r'[A-Za-z0-9_-]{1,255}', signature_id) is None:
                raise _invalid_response('System One X-Signature-Id')
            try:
                response_body = await response.aread()
            except httpx.HTTPError as error:
                raise api_failure(
                    'api.transport_failed',
                    {'resource': 'completion', 'reason': 'response_body'},
                    cause=error,
                ) from error
        finally:
            await response.aclose()
        try:
            data = SystemOneResponseSchema.model_validate_json(response_body)
        except ValidationError:
            raise _invalid_response('System One response') from None
        _validate_answers(parsed, data)

        async def verify() -> VerifiedCompletionResult:
            signature = await session.attestation_client.fetch_completion_signature(
                signature_id, signing_algo=client._signing_algo
            )
            if signature.signer.signing_algo != client._signing_algo:
                raise verification_failure('signature.signer_mismatch')
            return session.verify_response(
                signature_id, request_body, response_body, signature
            )

        return SystemOneResult(
            data=cast(SystemOneResponse, data.model_dump(exclude_unset=True)),
            signature_id=signature_id,
            _verify=verify,
        )


def _validate_answers(
    request: SystemOneRequestSchema, response: SystemOneResponseSchema
) -> None:
    if (
        response.usage.input_tokens + response.usage.output_tokens > 2147483647
        or request.questions.keys() != response.answers.keys()
    ):
        raise _invalid_response('System One answers or usage')
    for name, question in request.questions.items():
        answer = response.answers[name]
        if question.type != answer.type:
            raise _invalid_response('System One answer type')
        if question.type == 'choice' and answer.type == 'choice':
            if (
                answer.choice not in question.criteria
                or question.criteria.keys() != answer.probabilities.keys()
            ):
                raise _invalid_response('System One choice')
        if question.type == 'score' and answer.type == 'score':
            levels = {str(index) for index in range(len(question.criteria))}
            if (
                not 0 <= answer.score <= len(levels) - 1
                or levels != answer.probabilities.keys()
                or levels != answer.legend.keys()
            ):
                raise _invalid_response('System One score')


def _invalid_input(expected: str) -> ApiError:
    return api_failure(
        'api.invalid_input',
        {'field': 'systemone', 'reason': 'unsupported_value', 'expected': expected},
    )


def _invalid_response(path: str) -> ApiError:
    return api_failure(
        'api.invalid_response',
        {
            'path': path,
            'expected': 'a valid System One response and receipt ID',
            'actual': 'missing or invalid',
        },
    )
