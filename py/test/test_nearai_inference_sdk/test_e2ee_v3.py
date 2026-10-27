"""Shared vectors generated independently with cryptography and libsodium."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from nacl.signing import SigningKey

from nearai_inference_sdk.core.e2ee import (
    EcdsaE2eeClientKeyPair,
    Ed25519E2eeClientKeyPair,
    build_e2ee_request_aad,
    create_e2ee_client_key_pair,
    decrypt_e2ee_text,
    e2ee_field_aad,
    encrypt_e2ee_text,
)
from nearai_inference_sdk.core.e2ee_chat import (
    decrypt_e2ee_chat_response,
    decrypt_e2ee_chat_sse,
    parse_e2ee_chat_response,
)
from nearai_inference_sdk.types.e2ee import E2eeModelKey
from nearai_inference_sdk.utils.errors import VerificationError

VECTORS = json.loads(
    (Path(__file__).parents[3] / 'test-fixtures/e2ee-v3.json').read_text()
)['vectors']


@pytest.mark.parametrize('vector', VECTORS, ids=lambda v: v['signing_algo'])
def test_v3_shared_vectors(vector):
    algo = vector['signing_algo']
    seed = bytes.fromhex(vector['model_secret'])
    key = (
        EcdsaE2eeClientKeyPair(
            public_key=vector['model_public'],
            private_key=ec.derive_private_key(
                int.from_bytes(seed, 'big'), ec.SECP256K1()
            ),
        )
        if algo == 'ecdsa'
        else Ed25519E2eeClientKeyPair(
            public_key=vector['model_public'],
            x25519_secret_key=bytes(SigningKey(seed).to_curve25519_private_key()),
        )
    )
    aad = e2ee_field_aad(
        build_e2ee_request_aad(
            E2eeModelKey(signing_algo=algo, public_key=vector['reply_public'])
        ),
        'messages[].content',
    )
    assert aad.hex() == vector['aad']
    assert (
        decrypt_e2ee_text(vector['ciphertext'], key, 'request', aad)
        == vector['plaintext']
    )
    if algo == 'ecdsa':
        assert (
            e2ee_field_aad(
                build_e2ee_request_aad(
                    E2eeModelKey(
                        signing_algo=algo, public_key=vector['reply_public'][2:]
                    )
                ),
                'messages[].content',
            )
            == aad
        )
    model = E2eeModelKey(signing_algo=algo, public_key=vector['model_public'])
    cipher = encrypt_e2ee_text(vector['plaintext'], model, aad)
    assert decrypt_e2ee_text(cipher, key, 'request', aad) == vector['plaintext']
    for wrong in [
        b'',
        e2ee_field_aad(build_e2ee_request_aad(model), 'messages[].content'),
        e2ee_field_aad(
            build_e2ee_request_aad(
                E2eeModelKey(signing_algo=algo, public_key=vector['reply_public'])
            ),
            'tool_choice.function.name',
        ),
        aad[:22] + b'\xff' + aad[23:],
    ]:
        with pytest.raises(VerificationError):
            decrypt_e2ee_text(vector['ciphertext'], key, 'request', wrong)
    for choice in [
        {'message': {}, 'logprobs': {'content': [{'bytes': [115]}]}},
        {'message': {'tool_calls': [{'function': {'arguments': '{}'}}]}},
        {'message': {'tool_calls': [{'function': {'arguments': {'secret': True}}}]}},
    ]:
        with pytest.raises(VerificationError):
            decrypt_e2ee_chat_response({'choices': [choice]}, key)


@pytest.mark.parametrize('algo', ['ecdsa', 'ed25519'])
@pytest.mark.parametrize('streaming', [False, True])
def test_v3_validates_rich_content_parts(algo, streaming):
    key = create_e2ee_client_key_pair(algo)
    model = E2eeModelKey(signing_algo=algo, public_key=key.public_key)
    part = {'type': 'text', 'text': encrypt_e2ee_text('answer', model)}
    field = 'delta' if streaming else 'message'

    def decrypt(content):
        return decrypt_e2ee_chat_response(
            {'choices': [{field: {'content': content}}]}, key, streaming=streaming
        )

    assert decrypt([part])['choices'][0][field]['content'] == [
        {'type': 'text', 'text': 'answer'}
    ]
    assert decrypt([])['choices'][0][field]['content'] == []
    for invalid in ['plaintext', 0, True, None, ['nested']]:
        with pytest.raises(VerificationError) as error:
            decrypt([part, invalid])
        assert error.value.failure.code == 'e2ee.decryption_failed'


@pytest.mark.asyncio
@pytest.mark.parametrize('algo', ['ecdsa', 'ed25519'])
async def test_rejects_malformed_protected_containers_in_json_and_sse(algo):
    key = create_e2ee_client_key_pair(algo)
    choices = [
        {'message': {'tool_calls': {'function': {'arguments': 'plaintext'}}}},
        {'message': {'tool_calls': [None]}},
        {'message': {'tool_calls': [{'function': ['plaintext']}]}},
        {'message': {'audio': [{'data': 'plaintext'}]}},
        {'message': {'function_call': ['plaintext']}},
        {'logprobs': []},
        {'logprobs': {'content': {'token': 'plaintext'}}},
        {'logprobs': {'content': [None]}},
        {'logprobs': {'content': [{'top_logprobs': {'token': 'plaintext'}}]}},
    ]
    for choice in choices:
        body = {'id': 'chat-containers', 'choices': [choice]}
        with pytest.raises(VerificationError):
            decrypt_e2ee_chat_response(parse_e2ee_chat_response(body), key)
        if 'message' in choice:
            choice = {'delta': choice['message']}
        chunk = {'id': 'chat-containers', 'choices': [choice]}

        async def source(chunk=chunk):
            yield f'data: {json.dumps(chunk)}\n\n'.encode()

        with pytest.raises(VerificationError):
            async for _ in decrypt_e2ee_chat_sse(source(), key):
                pass
    # A tool-call fragment may introduce the id before sending its function.
    valid = {
        'id': 'chat-fragment',
        'choices': [
            {
                'delta': {'tool_calls': [{'index': 0, 'id': 'call-1'}], 'audio': None},
                'logprobs': None,
            }
        ],
    }
    assert decrypt_e2ee_chat_response(valid, key, streaming=True) == valid
