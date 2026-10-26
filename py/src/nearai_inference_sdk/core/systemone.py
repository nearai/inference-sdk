"""Non-streaming decisions: one inference attempt, independently retryable receipt."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from contextlib import suppress
from typing import TYPE_CHECKING, cast

import httpx
from pydantic import ValidationError

from ..schemas import (
    CompletionRequestModelSchema,
    CompletionResponseIdSchema,
    SystemOneResponseSchema,
)
from ..types.cloud_api import NO_ALIASING_HEADER
from ..types.systemone import SystemOneRequest, SystemOneResponse, SystemOneResult
from ..utils.errors import (
    ApiError,
    VerificationError,
    api_failure,
)
from .body_limit import (
    read_bounded_body,
    read_bounded_request_body,
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
                'accept-encoding': 'identity',
            }
        )
        http_request = httpx.Request(
            'POST',
            httpx.URL(client.base_url).join('systemone'),
            headers=request_headers,
            content=request_body,
        )
        response, register = await self._capture(http_request, request_headers)
        try:
            data = SystemOneResponseSchema.model_validate_json(response.content)
        except ValidationError:
            raise _invalid_response('System One response') from None
        register()
        return SystemOneResult(
            data=cast(SystemOneResponse, data.model_dump(exclude_unset=True)),
            decision_id=response.headers['x-generation-id'],
        )

    async def _send(self, request: httpx.Request) -> httpx.Response:
        """Retain exact JSON bytes; the external SDK owns response parsing."""
        headers = self._client._request_headers(request.headers)
        response, register = await self._capture(request, headers)
        register()
        return response

    async def _capture(
        self, request: httpx.Request, headers: httpx.Headers
    ) -> tuple[httpx.Response, Callable[[], None]]:
        client = self._client
        if client._e2ee or client._ohttp:
            raise _invalid_input('System One requires e2ee=False and ohttp=False')
        # Both entry points merge configured headers exactly once. Native create()
        # also removes headers belonging to the body it replaces.
        request_headers = httpx.Headers(headers)
        encoding = request_headers.get('content-encoding', '').strip().lower()
        content_type = request_headers.get('content-type', '').split(';')[0].strip()
        if (
            encoding not in ('', 'identity')
            or content_type.lower() != 'application/json'
        ):
            raise _invalid_input('an uncompressed JSON System One request')
        request_body = await read_bounded_request_body(
            request, client._response_byte_limit(0)
        )
        response_limit = client._response_byte_limit(len(request_body))
        try:
            parsed = json.loads(request_body)
        except ValueError as cause:
            raise _invalid_input(
                'a JSON System One request with a non-empty model'
            ) from cause
        try:
            model = CompletionRequestModelSchema.model_validate(parsed).model
        except ValidationError as cause:
            raise api_failure(
                'api.invalid_input',
                {
                    'field': 'model',
                    'reason': 'missing_model',
                    'expected': 'a non-empty model ID',
                },
                cause=cause,
            ) from cause
        if 'stream' in parsed:
            raise _invalid_input('System One does not support streaming')
        remove_e2ee_headers(request_headers)
        for name in ('content-length', 'transfer-encoding', 'trailer'):
            request_headers.pop(name, None)
        request_headers[NO_ALIASING_HEADER] = 'true'
        request_headers['accept'] = 'application/json'
        request_headers['accept-encoding'] = 'identity'
        http_request = httpx.Request(
            request.method,
            request.url,
            headers=request_headers,
            content=request_body,
            extensions=request.extensions,
        )
        session = await client._start_verification(model)
        if session.model_key is not None:
            http_request.headers['x-model-pub-key'] = session.model_key.public_key
        try:
            response = await session.http_client.send(http_request, stream=True)
        except (ApiError, VerificationError):
            raise
        except httpx.HTTPError as error:
            raise api_failure(
                'api.transport_failed',
                {'resource': 'systemone', 'reason': 'request'},
                cause=error,
            ) from error
        try:
            if not response.is_success:
                # Do not retain error bodies, which can contain private state.
                raise api_failure(
                    'api.http_status',
                    {'resource': 'systemone', 'status': response.status_code},
                )
            try:
                decision_id = CompletionResponseIdSchema.model_validate(
                    {'id': response.headers.get('x-generation-id')}
                ).id
            except ValidationError:
                raise _invalid_response('System One X-Generation-Id') from None
            try:
                response_body = await read_bounded_body(
                    response.aiter_bytes(), response_limit
                )
            except httpx.HTTPError as error:
                raise api_failure(
                    'api.transport_failed',
                    {'resource': 'systemone', 'reason': 'response_body'},
                    cause=error,
                ) from error
        finally:
            with suppress(Exception):
                await response.aclose()

        def register() -> None:
            captured = asyncio.get_running_loop().create_future()
            captured.set_result(response_body)
            client._register_response(decision_id, request_body, captured, session)

        # HTTPX decodes the body but retains the original compression headers.
        response_headers = response.headers.copy()
        response_headers.pop('content-encoding', None)
        response_headers.pop('content-length', None)
        return httpx.Response(
            response.status_code,
            headers=response_headers,
            content=response_body,
            extensions=response.extensions,
            request=http_request,
        ), register


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
