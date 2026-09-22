"""Standalone preparation, protocol field coverage, and streaming decryption."""

import gzip
import json

import httpx
import pytest

from nearai_inference_sdk.core.e2ee import (
    create_e2ee_client_key_pair,
    decrypt_e2ee_text,
    encrypt_e2ee_text,
)
from nearai_inference_sdk.core.e2ee_request import prepare_e2ee_chat_request
from nearai_inference_sdk.types.e2ee import E2eeModelKey
from nearai_inference_sdk.utils.errors import ApiError, VerificationError
from nearai_inference_sdk.utils.sse import get_sse_data_records


ENDPOINT = 'https://gateway.test/v1/chat/completions'
PROMPT = {'model': 'test-model', 'messages': [{'role': 'user', 'content': '私密问题'}]}


@pytest.fixture(params=['ed25519', 'ecdsa'])
def signing_algo(request):
    return request.param


class ByteStream(httpx.AsyncByteStream):
    def __init__(self, content: bytes):
        self.content = content
        self.closed = False

    async def __aiter__(self):
        for byte in self.content:
            yield bytes([byte])

    async def aclose(self):
        self.closed = True


def model_keys(signing_algo):
    pair = create_e2ee_client_key_pair(signing_algo)
    return E2eeModelKey(signing_algo=signing_algo, public_key=pair.public_key), pair


def response_key(prepared, signing_algo):
    return E2eeModelKey(
        signing_algo=signing_algo,
        public_key=prepared.request.headers['x-client-pub-key'],
    )


@pytest.mark.asyncio
async def test_prepares_headers_and_encrypts_supported_request_fields(signing_algo):
    model_key, pair = model_keys(signing_algo)
    body = {
        'model': 'test-model',
        'messages': [
            {
                'role': 'assistant',
                'content': [{'type': 'text', 'text': '私密问题'}],
                'reasoning': 'reason',
                'reasoning_content': 'thought',
                'name': 'helper',
                'refusal': 'refused',
                'audio': {'data': 'audio-bytes', 'format': 'wav'},
                'tool_calls': [
                    {'id': 'call-1', 'function': {'name': 'search', 'arguments': '{}'}}
                ],
                'function_call': {'name': 'legacy', 'arguments': '{}'},
            }
        ],
        'tools': [
            {
                'type': 'function',
                'function': {
                    'name': 'search',
                    'description': 'lookup',
                    'parameters': {},
                },
            }
        ],
        'tool_choice': {'type': 'function', 'function': {'name': 'search'}},
        'function_call': {'name': 'legacy'},
        'future_option': {'enabled': True},
    }
    original = httpx.Request(
        'POST',
        ENDPOINT,
        json=body,
        headers={
            'authorization': 'Bearer caller-owned',
            'Content-Length': '999',
            'Content-MD5': 'stale',
            'Digest': 'sha-256=stale',
            'Content-Digest': 'sha-256=:stale:',
            'Repr-Digest': 'sha-256=:stale:',
            'Content-Encoding': 'gzip',
            'x-encryption-version': 'stale',
        },
        extensions={'timeout': {'read': None}},
    )
    prepared = await prepare_e2ee_chat_request(original, model_key)
    headers = prepared.request.headers
    assert headers['authorization'] == 'Bearer caller-owned'
    assert headers['x-signing-algo'] == signing_algo
    assert headers['x-model-pub-key'] == model_key.public_key
    assert headers['x-encrypt-all-fields'] == 'true'
    assert headers['x-no-aliasing'] == 'true'
    assert headers.get('x-encryption-version') == (
        '2' if signing_algo == 'ed25519' else None
    )
    assert headers['content-length'] == str(len(prepared.request.content))
    for name in (
        'content-md5',
        'digest',
        'content-digest',
        'repr-digest',
        'content-encoding',
    ):
        assert name not in headers
    assert prepared.request.extensions == original.extensions
    encrypted = json.loads(await prepared.request.aread())
    message = encrypted['messages'][0]
    assert (
        json.loads(decrypt_e2ee_text(message['content'], pair, 'content'))
        == body['messages'][0]['content']
    )
    for field in ('reasoning', 'reasoning_content', 'name', 'refusal'):
        assert (
            decrypt_e2ee_text(message[field], pair, field) == body['messages'][0][field]
        )
    assert decrypt_e2ee_text(message['audio']['data'], pair, 'audio') == 'audio-bytes'
    for field in ('name', 'arguments'):
        assert (
            decrypt_e2ee_text(message['tool_calls'][0]['function'][field], pair, field)
            == body['messages'][0]['tool_calls'][0]['function'][field]
        )
        assert (
            decrypt_e2ee_text(message['function_call'][field], pair, field)
            == body['messages'][0]['function_call'][field]
        )
    function = encrypted['tools'][0]['function']
    assert decrypt_e2ee_text(function['name'], pair, 'name') == 'search'
    assert decrypt_e2ee_text(function['description'], pair, 'description') == 'lookup'
    assert (
        json.loads(decrypt_e2ee_text(function['parameters'], pair, 'parameters')) == {}
    )
    assert (
        decrypt_e2ee_text(encrypted['tool_choice']['function']['name'], pair, 'name')
        == 'search'
    )
    assert (
        decrypt_e2ee_text(encrypted['function_call']['name'], pair, 'name') == 'legacy'
    )
    assert encrypted['future_option'] == body['future_option']
    assert json.loads(await original.aread()) == body


@pytest.mark.asyncio
async def test_encrypts_async_request_body_with_buffered_framing():
    model_key, pair = model_keys('ed25519')
    request = httpx.Request(
        'POST',
        ENDPOINT,
        content=ByteStream(json.dumps(PROMPT).encode()),
        headers={'Content-Type': 'application/json', 'Trailer': 'Digest'},
    )

    prepared = await prepare_e2ee_chat_request(request, model_key)

    assert 'transfer-encoding' not in prepared.request.headers
    assert 'trailer' not in prepared.request.headers
    assert prepared.request.headers['content-length'] == str(
        len(prepared.request.content)
    )
    encrypted = json.loads(prepared.request.content)
    assert (
        decrypt_e2ee_text(encrypted['messages'][0]['content'], pair, 'content')
        == PROMPT['messages'][0]['content']
    )


@pytest.mark.asyncio
async def test_decrypts_json_fields_and_preserves_http_metadata(signing_algo):
    model_key, _ = model_keys(signing_algo)
    prepared = await prepare_e2ee_chat_request(
        httpx.Request('POST', ENDPOINT, json=PROMPT), model_key
    )
    client_key = response_key(prepared, signing_algo)

    def encrypt(value):
        return encrypt_e2ee_text(value, client_key)

    body = {
        'id': 'chat-1',
        'choices': [
            {
                'message': {
                    'content': [{'type': 'text', 'text': encrypt('回答')}],
                    'reasoning': encrypt('reason'),
                    'reasoning_content': encrypt('thought'),
                    'refusal': '',
                    'audio': {'data': encrypt('audio')},
                    'tool_calls': [
                        {
                            'id': 'call-1',
                            'function': {
                                'name': encrypt('search'),
                                'arguments': encrypt('{}'),
                            },
                        }
                    ],
                    'function_call': {
                        'name': encrypt('legacy'),
                        'arguments': encrypt('{}'),
                    },
                },
                'logprobs': {
                    'content': [
                        {
                            'token': encrypt('a'),
                            'bytes': encrypt('[97]'),
                            'top_logprobs': [
                                {'token': encrypt('b'), 'bytes': encrypt('[98]')}
                            ],
                        }
                    ]
                },
            }
        ],
        'usage': {'total_tokens': 5},
    }
    # Source decoding removes gzip once. The transformed response must not
    # advertise gzip and attempt to decompress its already-decrypted JSON.
    source = httpx.Response(
        201,
        content=gzip.compress(json.dumps(body).encode()),
        headers={
            'Content-Encoding': 'gzip',
            'Content-MD5': 'stale',
            'Digest': 'sha-256=stale',
            'Content-Digest': 'sha-256=:stale:',
            'Repr-Digest': 'sha-256=:stale:',
            'x-result': 'preserved',
        },
        extensions={'http_version': b'HTTP/2'},
        request=prepared.request,
    )
    response = await prepared.decrypt_response(source)
    decrypted = response.json()
    message = decrypted['choices'][0]['message']
    assert message['content'][0]['text'] == '回答'
    assert message['reasoning'] == 'reason'
    assert message['reasoning_content'] == 'thought'
    assert message['refusal'] == ''
    assert message['audio']['data'] == 'audio'
    assert message['tool_calls'][0]['function'] == {'name': 'search', 'arguments': '{}'}
    assert message['function_call'] == {'name': 'legacy', 'arguments': '{}'}
    assert decrypted['choices'][0]['logprobs']['content'] == [
        {'token': 'a', 'bytes': [97], 'top_logprobs': [{'token': 'b', 'bytes': [98]}]}
    ]
    assert decrypted['usage'] == body['usage']
    assert response.status_code == 201
    assert response.headers['x-result'] == 'preserved'
    assert response.headers['content-length'] == str(len(response.content))
    for name in (
        'content-encoding',
        'content-md5',
        'digest',
        'content-digest',
        'repr-digest',
    ):
        assert name not in response.headers
    assert response.extensions == source.extensions
    assert response.request is prepared.request


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'line_ending,separator',
    [('\n', '\n\n'), ('\r\n', '\r\n\r\n'), ('\r', '\r\r'), ('\r', '\n\n')],
    ids=['LF', 'CRLF', 'CR', 'mixed'],
)
async def test_decrypts_multiline_sse_across_split_bytes(
    signing_algo, line_ending, separator
):
    model_key, _ = model_keys(signing_algo)
    prepared = await prepare_e2ee_chat_request(
        httpx.Request('POST', ENDPOINT, json={**PROMPT, 'stream': True}), model_key
    )
    client_key = response_key(prepared, signing_algo)
    delta = {
        'content': encrypt_e2ee_text('流式回答', client_key),
        'nearai_tool_result': {'output': encrypt_e2ee_text('tool output', client_key)},
    }
    prefix = f': 保活{separator}event: message{line_ending}id: part-1{line_ending}'
    data = f'data: {{"id":"chat-1",{line_ending}data: "choices":{json.dumps([{"delta": delta}])}}}'
    suffix = 'event: error\ndata: {"message":"unchanged"}\n\ndata:\n\ndata\n\ndata: [DONE]\n\n'
    source = ByteStream((prefix + data + separator + suffix).encode())
    response = await prepared.decrypt_response(
        httpx.Response(
            200,
            stream=source,
            headers={
                'content-type': 'text/event-stream',
                'Content-Length': str(len(source.content)),
                'Content-MD5': 'stale',
                'Digest': 'sha-256=stale',
                'Content-Digest': 'sha-256=:stale:',
                'Repr-Digest': 'sha-256=:stale:',
            },
        )
    )
    for name in (
        'content-length',
        'content-md5',
        'digest',
        'content-digest',
        'repr-digest',
    ):
        assert name not in response.headers
    text = (await response.aread()).decode()
    assert text.startswith(prefix)
    assert text.endswith(suffix)
    payload = next(
        value for value in get_sse_data_records(text) if value.startswith('{"id"')
    )
    assert json.loads(payload)['choices'][0]['delta'] == {
        'content': '流式回答',
        'nearai_tool_result': {'output': 'tool output'},
    }
    assert source.closed


@pytest.mark.asyncio
async def test_rejects_ciphertext_for_a_different_request_key(signing_algo):
    model_key, _ = model_keys(signing_algo)
    first = await prepare_e2ee_chat_request(
        httpx.Request('POST', ENDPOINT, json=PROMPT), model_key
    )
    second = await prepare_e2ee_chat_request(
        httpx.Request('POST', ENDPOINT, json=PROMPT), model_key
    )
    ciphertext = encrypt_e2ee_text(
        'only for first request', response_key(first, signing_algo)
    )
    body = {'choices': [{'message': {'content': ciphertext}}]}
    decrypted = await first.decrypt_response(httpx.Response(200, json=body))
    assert (
        decrypted.json()['choices'][0]['message']['content'] == 'only for first request'
    )
    with pytest.raises(VerificationError) as error:
        await second.decrypt_response(httpx.Response(200, json=body))
    assert error.value.failure.code == 'e2ee.decryption_failed'
    assert error.value.failure.details == {'field': 'choices[0].message.content'}


@pytest.mark.asyncio
async def test_closing_a_decrypted_stream_closes_its_source():
    model_key, _ = model_keys('ed25519')
    prepared = await prepare_e2ee_chat_request(
        httpx.Request('POST', ENDPOINT, json=PROMPT), model_key
    )
    source = ByteStream(b'data: [DONE]\n\n')
    response = await prepared.decrypt_response(
        httpx.Response(
            200, stream=source, headers={'content-type': 'text/event-stream'}
        )
    )
    await response.aclose()
    assert source.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'content,code',
    [
        (b'data: \xff\n\n', 'api.invalid_response'),
        (b'data: {not-json}\n\n', 'api.invalid_response'),
        (
            b'data: {"choices":[{"delta":{"content":"00"}}]}\n\n',
            'e2ee.decryption_failed',
        ),
    ],
    ids=['invalid-utf8', 'invalid-json', 'invalid-ciphertext'],
)
async def test_stream_failure_closes_source_and_reports_the_failed_boundary(
    content, code
):
    model_key, _ = model_keys('ed25519')
    prepared = await prepare_e2ee_chat_request(
        httpx.Request('POST', ENDPOINT, json=PROMPT), model_key
    )
    source = ByteStream(content)
    response = await prepared.decrypt_response(
        httpx.Response(
            200, stream=source, headers={'content-type': 'text/event-stream'}
        )
    )
    with pytest.raises((ApiError, VerificationError)) as error:
        await response.aread()
    assert error.value.failure.code == code
    assert source.closed


@pytest.mark.asyncio
async def test_rejects_invalid_http_bodies_without_leaking_schema_errors():
    model_key, _ = model_keys('ed25519')
    with pytest.raises(ApiError) as error:
        await prepare_e2ee_chat_request(
            httpx.Request('POST', ENDPOINT, json={'model': 123}), model_key
        )
    assert error.value.failure.code == 'api.invalid_input'
    prepared = await prepare_e2ee_chat_request(
        httpx.Request('POST', ENDPOINT, json=PROMPT), model_key
    )
    with pytest.raises(ApiError) as error:
        await prepared.decrypt_response(httpx.Response(200, json=[]))
    assert error.value.failure.code == 'api.invalid_response'
    upstream_error = httpx.Response(429, text='retry later')
    assert await prepared.decrypt_response(upstream_error) is upstream_error
