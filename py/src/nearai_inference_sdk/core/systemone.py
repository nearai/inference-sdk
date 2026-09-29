"""Non-streaming decisions: one inference attempt, independently retryable receipt."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

import httpx
from pydantic import ValidationError

from ..schemas import CompletionResponseIdSchema, SystemOneResponseSchema
from ..types.cloud_api import NO_ALIASING_HEADER
from ..types.systemone import SystemOneRequest, SystemOneResponse, SystemOneResult
from ..utils.errors import (
    ApiError,
    VerificationError,
    api_failure,
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
        """Send once; pass result.decision_id to client.verify_response()."""

        client = self._client
        if client._e2ee or client._ohttp:
            raise _invalid_input('System One requires e2ee=False and ohttp=False')
        if 'stream' in request:
            raise _invalid_input('System One does not support streaming')
        try:
            request_body = json.dumps(request, allow_nan=False).encode()
        except (ValueError, TypeError):
            raise _invalid_input('a JSON-serializable System One request') from None
        # Leave request business rules to the server and retain the exact bytes.
        session = await client._start_verification(
            request['model'], endpoint='systemone'
        )
        request_headers = client._request_headers(headers or {})
        remove_e2ee_headers(request_headers)
        for name in (
            'content-length',
            'content-encoding',
            'transfer-encoding',
            'trailer',
            'content-md5',
            'digest',
            'content-digest',
            'repr-digest',
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
            try:
                decision_id = CompletionResponseIdSchema.model_validate(
                    {'id': response.headers.get('x-generation-id')}
                ).id
            except ValidationError:
                raise _invalid_response('System One X-Generation-Id') from None
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
        captured = asyncio.get_running_loop().create_future()
        captured.set_result(response_body)
        client._register_response(decision_id, request_body, captured, session)

        return SystemOneResult(
            data=cast(SystemOneResponse, data.model_dump(exclude_unset=True)),
            decision_id=decision_id,
        )


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
