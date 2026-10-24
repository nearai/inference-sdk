"""Selective Chat Completions field transforms, including streamed responses."""

from __future__ import annotations

import json
from collections.abc import AsyncIterable, AsyncIterator, Callable
from copy import deepcopy
from io import StringIO
from typing import Any

from pydantic import ValidationError

from ..schemas import ChatCompletionResponseSchema
from ..types.attestation_common import SigningAlgo
from ..types.e2ee import E2eeModelKey
from ..utils.errors import ApiError, api_failure, verification_failure
from ..utils.sse import (
    SseDecoder,
    get_sse_data,
    get_sse_record_data,
    iter_sse_lines,
)
from .e2ee import E2eeClientKeyPair, decrypt_e2ee_text, encrypt_e2ee_text


def parse_e2ee_chat_response(body: object) -> dict[str, Any]:
    """Establish the JSON-object boundary without restricting future fields."""

    try:
        return ChatCompletionResponseSchema.model_validate(body).root
    except ValidationError as cause:
        raise _invalid_response('Chat Completions response', cause) from cause


def encrypt_e2ee_chat_request(
    body: dict[str, Any], model_key: E2eeModelKey
) -> dict[str, Any]:
    """Encrypt only protocol-supported fields, leaving ordinary Chat JSON alone."""

    return _transform_request(body, lambda value: encrypt_e2ee_text(value, model_key))


def measure_e2ee_chat_request_bytes(
    body: dict[str, Any], signing_algo: SigningAlgo
) -> int:
    """Measure wire JSON using the encryption traversal, without keys or ciphertext."""

    envelope_bytes = 65 + 12 + 16 if signing_algo == 'ecdsa' else 32 + 24 + 16
    ciphertext_bytes = 0

    def measure(value: str) -> str:
        nonlocal ciphertext_bytes
        ciphertext_bytes += 2 * (len(value.encode('utf-8')) + envelope_bytes)
        return ''

    skeleton = _transform_request(body, measure)
    # Hex needs no JSON escaping; empty placeholders preserve quotes and punctuation.
    return len(_json(skeleton).encode('utf-8')) + ciphertext_bytes


def _transform_request(
    body: dict[str, Any], encrypt: Callable[[str], str]
) -> dict[str, Any]:
    encrypted = deepcopy(body)
    for message in _objects(encrypted.get('messages')):
        content = message.get('content')
        if isinstance(content, str):
            message['content'] = encrypt(content)
        elif isinstance(content, list):
            message['content'] = encrypt(_json(content))
        _encrypt_fields(
            message,
            ('reasoning_content', 'reasoning', 'name', 'refusal'),
            encrypt,
        )
        if isinstance(message.get('audio'), dict):
            _encrypt_fields(message['audio'], ('data',), encrypt)
        for tool_call in _objects(message.get('tool_calls')):
            if isinstance(tool_call.get('function'), dict):
                _encrypt_fields(tool_call['function'], ('name', 'arguments'), encrypt)
        if isinstance(message.get('function_call'), dict):
            _encrypt_fields(message['function_call'], ('name', 'arguments'), encrypt)

    for tool in _objects(encrypted.get('tools')):
        function = tool.get('function')
        if not isinstance(function, dict):
            continue
        _encrypt_fields(function, ('name', 'description'), encrypt)
        if 'parameters' in function:
            function['parameters'] = encrypt(_json(function['parameters']))
    tool_choice = encrypted.get('tool_choice')
    if isinstance(tool_choice, dict) and isinstance(tool_choice.get('function'), dict):
        _encrypt_fields(tool_choice['function'], ('name',), encrypt)
    if isinstance(encrypted.get('function_call'), dict):
        _encrypt_fields(encrypted['function_call'], ('name',), encrypt)
    return encrypted


def decrypt_e2ee_chat_response(
    body: dict[str, Any], client_key_pair: E2eeClientKeyPair, *, streaming: bool = False
) -> dict[str, Any]:
    """Decrypt documented response fields without modifying the wire body."""

    decrypted = deepcopy(body)
    choices = decrypted.get('choices')
    if not isinstance(choices, list):
        return decrypted
    for index, choice in enumerate(choices):
        if not isinstance(choice, dict):
            continue
        path = f'choices[{index}]'
        field = 'delta' if streaming else 'message'
        message = choice.get(field)
        if isinstance(message, dict):
            _decrypt_message(message, client_key_pair, f'{path}.{field}')
            if streaming and isinstance(message.get('nearai_tool_result'), dict):
                _decrypt_fields(
                    message['nearai_tool_result'],
                    ('output',),
                    client_key_pair,
                    f'{path}.{field}.nearai_tool_result',
                )
        logprobs = choice.get('logprobs')
        if isinstance(logprobs, dict):
            for logprob_field in ('content', 'refusal'):
                _decrypt_logprobs(
                    logprobs.get(logprob_field),
                    client_key_pair,
                    f'{path}.logprobs.{logprob_field}',
                )
    return decrypted


async def decrypt_e2ee_chat_sse(
    source: AsyncIterable[bytes], client_key_pair: E2eeClientKeyPair
) -> AsyncIterator[bytes]:
    """Preserve SSE controls and boundaries, even across split UTF-8 or CRLF."""

    decoder = SseDecoder()
    try:
        async for chunk in source:
            buffered = bytearray()
            for record in decoder.feed(chunk):
                buffered.extend(
                    _transform_sse_record(
                        record.value, record.separator, client_key_pair
                    ).encode()
                )
                if len(buffered) >= 64 * 1024:
                    yield bytes(buffered)
                    buffered.clear()
            if buffered:
                yield bytes(buffered)
        pending = decoder.finish()
        if pending:
            yield _transform_sse_record(pending, '', client_key_pair).encode()
    except UnicodeDecodeError as cause:
        raise _invalid_response('Chat Completions SSE response', cause) from cause


def _encrypt_fields(
    target: dict[str, Any], fields: tuple[str, ...], encrypt: Callable[[str], str]
) -> None:
    for field in fields:
        value = target.get(field)
        if isinstance(value, str):
            target[field] = encrypt(value)


def _decrypt_fields(
    target: dict[str, Any],
    fields: tuple[str, ...],
    client_key_pair: E2eeClientKeyPair,
    path: str,
) -> None:
    for field in fields:
        value = target.get(field)
        if isinstance(value, str):
            target[field] = decrypt_e2ee_text(value, client_key_pair, f'{path}.{field}')


def _decrypt_message(
    message: dict[str, Any], client_key_pair: E2eeClientKeyPair, path: str
) -> None:
    _decrypt_fields(
        message,
        ('content', 'reasoning_content', 'reasoning', 'refusal'),
        client_key_pair,
        path,
    )
    content = message.get('content')
    if isinstance(content, list):
        for index, part in enumerate(content):
            if isinstance(part, dict):
                _decrypt_fields(
                    part, ('text',), client_key_pair, f'{path}.content[{index}]'
                )
    if isinstance(message.get('audio'), dict):
        _decrypt_fields(message['audio'], ('data',), client_key_pair, f'{path}.audio')
    calls = message.get('tool_calls')
    if isinstance(calls, list):
        for index, call in enumerate(calls):
            if isinstance(call, dict) and isinstance(call.get('function'), dict):
                _decrypt_fields(
                    call['function'],
                    ('name', 'arguments'),
                    client_key_pair,
                    f'{path}.tool_calls[{index}].function',
                )
    if isinstance(message.get('function_call'), dict):
        _decrypt_fields(
            message['function_call'],
            ('name', 'arguments'),
            client_key_pair,
            f'{path}.function_call',
        )


def _decrypt_logprobs(
    entries: object, client_key_pair: E2eeClientKeyPair, path: str
) -> None:
    if not isinstance(entries, list):
        return
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        entry_path = f'{path}[{index}]'
        _decrypt_fields(entry, ('token',), client_key_pair, entry_path)
        raw_bytes = entry.get('bytes')
        if isinstance(raw_bytes, str):
            field_path = f'{entry_path}.bytes'
            value = decrypt_e2ee_text(raw_bytes, client_key_pair, field_path)
            try:
                entry['bytes'] = json.loads(value)
            except ValueError as cause:
                raise verification_failure(
                    'e2ee.decryption_failed', {'field': field_path}, cause=cause
                ) from cause
        _decrypt_logprobs(
            entry.get('top_logprobs'), client_key_pair, f'{entry_path}.top_logprobs'
        )


def _transform_sse_record(
    record: str, separator: str, client_key_pair: E2eeClientKeyPair
) -> str:
    data = get_sse_record_data(record)
    if data in ('', '[DONE]'):
        return record + separator
    event = None
    remaining = 0
    for line in iter_sse_lines(record):
        if get_sse_data(line.content) is not None:
            remaining += 1
        if event is None and line.content == 'event':
            event = ''
        elif event is None and line.content.startswith('event:'):
            event = line.content[len('event:') :].removeprefix(' ')
    if event == 'error':
        return record + separator
    try:
        body = json.loads(data)
    except ValueError as cause:
        raise _invalid_response('Chat Completions SSE data', cause) from cause
    chunk = parse_e2ee_chat_response(body)
    if 'choices' not in chunk:
        return record + separator
    decrypted = decrypt_e2ee_chat_response(chunk, client_key_pair, streaming=True)
    output = StringIO()
    for line in iter_sse_lines(record):
        if get_sse_data(line.content) is None:
            output.write(line.content + line.ending)
        else:
            remaining -= 1
            # Preserve the last data line's ending so mixed CR/LF cannot merge
            # into a single CRLF and erase the terminating blank line.
            if remaining == 0:
                output.write(f'data: {_json(decrypted)}{line.ending}')
    return output.getvalue() + separator


def _objects(value: object) -> list[dict[str, Any]]:
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def _invalid_response(path: str, cause: BaseException) -> ApiError:
    return api_failure(
        'api.invalid_response',
        {
            'path': path,
            'expected': 'a JSON Chat Completions object',
            'actual': 'invalid',
        },
        cause=cause,
    )
