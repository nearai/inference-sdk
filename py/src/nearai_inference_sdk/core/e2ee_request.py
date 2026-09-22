"""Standalone encrypted Chat requests with transport-independent decryption."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
from pydantic import ValidationError

from ..schemas import ChatCompletionRequestSchema
from ..types.e2ee import E2eeModelKey, PreparedE2eeChatRequest
from ..utils.errors import api_failure
from .e2ee import E2eeClientKeyPair, create_e2ee_client_key_pair
from .e2ee_chat import (
    decrypt_e2ee_chat_response,
    decrypt_e2ee_chat_sse,
    encrypt_e2ee_chat_request,
    parse_e2ee_chat_response,
)


_REPLACED_BODY_HEADERS = (
    'content-length',
    'transfer-encoding',
    'trailer',
    'content-md5',
    'digest',
    'content-digest',
    'repr-digest',
    'content-encoding',
)


async def prepare_e2ee_chat_request(
    request: httpx.Request, model_key: E2eeModelKey
) -> PreparedE2eeChatRequest:
    """Encrypt Chat fields for an already-verified key; perform no network I/O.

    Every call creates a fresh response key. The returned decryptor handles JSON
    and streaming SSE without exposing that private key. Keep the original wire
    request and response bytes separately when verifying a completion signature.
    """

    if request.method != 'POST':
        raise api_failure(
            'api.invalid_input',
            {
                'field': 'request',
                'reason': 'unsupported_value',
                'expected': 'a POST Chat Completions request',
                'actual': request.method,
            },
        )
    body = await decode_chat_request(request)
    client_key_pair = create_e2ee_client_key_pair(model_key.signing_algo)
    encrypted = encrypt_e2ee_chat_request(body, model_key)
    headers = httpx.Headers(request.headers)
    for name in _REPLACED_BODY_HEADERS:
        headers.pop(name, None)
    headers['content-type'] = 'application/json'
    remove_e2ee_headers(headers)
    headers['x-signing-algo'] = model_key.signing_algo
    headers['x-client-pub-key'] = client_key_pair.public_key
    headers['x-model-pub-key'] = model_key.public_key
    if model_key.signing_algo == 'ed25519':
        headers['x-encryption-version'] = '2'
    headers['x-no-aliasing'] = 'true'
    headers['x-encrypt-all-fields'] = 'true'

    async def decrypt_response(response: httpx.Response) -> httpx.Response:
        return await _decrypt_response(response, client_key_pair)

    return PreparedE2eeChatRequest(
        request=httpx.Request(
            request.method,
            request.url,
            headers=headers,
            json=encrypted,
            extensions=dict(request.extensions),
        ),
        decrypt_response=decrypt_response,
    )


async def decode_chat_request(request: httpx.Request) -> dict[str, Any]:
    """Read and validate the external HTTP request's minimal Chat boundary."""

    try:
        body = json.loads((await request.aread()).decode('utf-8'))
    except (ValueError, UnicodeError) as cause:
        raise api_failure(
            'api.invalid_input',
            {'field': 'request body', 'reason': 'invalid_json'},
            cause=cause,
        ) from cause
    try:
        return ChatCompletionRequestSchema.model_validate(body).model_dump()
    except ValidationError as cause:
        raise api_failure(
            'api.invalid_input',
            {
                'field': 'request body',
                'reason': 'unsupported_value',
                'expected': 'a JSON Chat Completions request with a string model',
            },
            cause=cause,
        ) from cause


def is_server_sent_event_response(response: httpx.Response) -> bool:
    return (
        response.headers.get('content-type', '').lower().startswith('text/event-stream')
    )


def remove_e2ee_headers(headers: httpx.Headers) -> None:
    for name in (
        'x-signing-algo',
        'x-client-pub-key',
        'x-model-pub-key',
        'x-encryption-version',
        'x-encrypt-all-fields',
    ):
        headers.pop(name, None)


async def _decrypt_response(
    response: httpx.Response, client_key_pair: E2eeClientKeyPair
) -> httpx.Response:
    if not response.is_success:
        return response
    headers = httpx.Headers(response.headers)
    # Decryption invalidates the wire length and digests. HTTPX already
    # decompresses source bytes, so the transformed body must not be decoded again.
    for name in _REPLACED_BODY_HEADERS:
        headers.pop(name, None)
    try:
        request = response.request
    except RuntimeError:
        request = None
    options = dict(
        status_code=response.status_code,
        headers=headers,
        extensions=dict(response.extensions),
        request=request,
    )
    if is_server_sent_event_response(response):
        return httpx.Response(
            **options, stream=_DecryptedSseStream(response, client_key_pair)
        )
    try:
        raw = await response.aread()
    except httpx.HTTPError as cause:
        raise api_failure(
            'api.transport_failed',
            {'resource': 'completion', 'reason': 'response_body'},
            retryable=True,
            cause=cause,
        ) from cause
    finally:
        await response.aclose()
    try:
        body = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError) as cause:
        raise api_failure(
            'api.invalid_response',
            {
                'path': 'Chat Completions response',
                'expected': 'a JSON Chat Completions object',
                'actual': 'invalid JSON',
            },
            cause=cause,
        ) from cause
    parsed = parse_e2ee_chat_response(body)
    decrypted = decrypt_e2ee_chat_response(parsed, client_key_pair)
    headers['content-type'] = 'application/json'
    return httpx.Response(**options, json=decrypted)


class _DecryptedSseStream(httpx.AsyncByteStream):
    def __init__(self, response: httpx.Response, client_key_pair: E2eeClientKeyPair):
        self.response = response
        self.client_key_pair = client_key_pair

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in decrypt_e2ee_chat_sse(
                self.response.aiter_bytes(), self.client_key_pair
            ):
                yield chunk
        finally:
            await self.response.aclose()

    async def aclose(self) -> None:
        await self.response.aclose()
