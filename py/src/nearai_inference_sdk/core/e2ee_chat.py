"""Selective Chat Completions field transforms, including streamed responses."""

from __future__ import annotations

import codecs
import json
from collections.abc import AsyncIterable, AsyncIterator
from copy import deepcopy
from typing import Any

from pydantic import ValidationError

from ..schemas import ChatCompletionResponseSchema
from ..types.e2ee import E2eeModelKey
from ..utils.errors import ApiError, api_failure, verification_failure
from ..utils.sse import get_sse_data, split_sse_lines, take_complete_sse_records
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

    encrypted = deepcopy(body)
    for message in _objects(encrypted.get('messages')):
        content = message.get('content')
        if isinstance(content, str):
            message['content'] = encrypt_e2ee_text(content, model_key)
        elif isinstance(content, list):
            message['content'] = encrypt_e2ee_text(_json(content), model_key)
        _encrypt_fields(
            message,
            ('reasoning_content', 'reasoning', 'name', 'refusal'),
            model_key,
        )
        if isinstance(message.get('audio'), dict):
            _encrypt_fields(message['audio'], ('data',), model_key)
        for tool_call in _objects(message.get('tool_calls')):
            if isinstance(tool_call.get('function'), dict):
                _encrypt_fields(tool_call['function'], ('name', 'arguments'), model_key)
        if isinstance(message.get('function_call'), dict):
            _encrypt_fields(message['function_call'], ('name', 'arguments'), model_key)

    for tool in _objects(encrypted.get('tools')):
        function = tool.get('function')
        if not isinstance(function, dict):
            continue
        _encrypt_fields(function, ('name', 'description'), model_key)
        if 'parameters' in function:
            function['parameters'] = encrypt_e2ee_text(
                _json(function['parameters']), model_key
            )
    tool_choice = encrypted.get('tool_choice')
    if isinstance(tool_choice, dict) and isinstance(tool_choice.get('function'), dict):
        _encrypt_fields(tool_choice['function'], ('name',), model_key)
    if isinstance(encrypted.get('function_call'), dict):
        _encrypt_fields(encrypted['function_call'], ('name',), model_key)
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

    decoder = codecs.getincrementaldecoder('utf-8')()
    pending = ''
    try:
        async for chunk in source:
            pending += decoder.decode(chunk)
            complete = take_complete_sse_records(pending)
            pending = complete.pending
            for record in complete.records:
                yield _transform_sse_record(
                    record.value, record.separator, client_key_pair
                ).encode()
        pending += decoder.decode(b'', final=True)
        if pending:
            yield _transform_sse_record(pending, '', client_key_pair).encode()
    except UnicodeDecodeError as cause:
        raise _invalid_response('Chat Completions SSE response', cause) from cause


def _encrypt_fields(
    target: dict[str, Any], fields: tuple[str, ...], model_key: E2eeModelKey
) -> None:
    for field in fields:
        value = target.get(field)
        if isinstance(value, str):
            target[field] = encrypt_e2ee_text(value, model_key)


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
    lines = split_sse_lines(record)
    data_lines = [
        data for line in lines if (data := get_sse_data(line.content)) is not None
    ]
    if not data_lines:
        return record + separator
    data = '\n'.join(data_lines)
    event = None
    for line in lines:
        if line.content == 'event':
            event = ''
            break
        if line.content.startswith('event:'):
            event = line.content[len('event:') :].removeprefix(' ')
            break
    if data in ('', '[DONE]') or event == 'error':
        return record + separator
    try:
        body = json.loads(data)
    except ValueError as cause:
        raise _invalid_response('Chat Completions SSE data', cause) from cause
    chunk = parse_e2ee_chat_response(body)
    if 'choices' not in chunk:
        return record + separator
    decrypted = decrypt_e2ee_chat_response(chunk, client_key_pair, streaming=True)
    remaining = len(data_lines)
    output = []
    for line in lines:
        if get_sse_data(line.content) is None:
            output.append(line.content + line.ending)
        else:
            remaining -= 1
            # Preserve the last data line's ending so mixed CR/LF cannot merge
            # into a single CRLF and erase the terminating blank line.
            if remaining == 0:
                output.append(f'data: {_json(decrypted)}{line.ending}')
    return ''.join(output) + separator


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
