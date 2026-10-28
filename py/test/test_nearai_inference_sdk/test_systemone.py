"""Decision requests preserve the public protocol and verify exact signed bytes."""

import asyncio
import gzip
import hashlib
import json
from dataclasses import replace

import brotli
import httpx
import pytest
from eth_account.messages import encode_defunct
from nacl.signing import SigningKey

from nearai_inference_sdk import (
    ApiError,
    AttestationVerifiers,
    GatewayVerificationOptions,
    ModelAttestationVerifiers,
    ModelVerificationOptions,
    SystemOneRequest,
    VerificationError,
    VerifiedModelCompletionResult,
)

from .test_inference_client import MESSAGES, MODEL, Gateway

IMAGE_PART = {
    'type': 'image_url',
    'image_url': {'url': 'data:image/png;base64,ZmFrZS1pbWFnZQ=='},
}
BOX_BOUNDS = {'top': 0.31, 'bottom': 0.69, 'left': 0.25, 'right': 0.75}
IMAGE_REQUEST = {
    'model': MODEL,
    'state': {'canvas': IMAGE_PART},
    'questions': {
        'region': {'type': 'box', 'instructions': ['Locate the rectangle', IMAGE_PART]},
        'present': {
            'type': 'noul',
            'instructions': 'Does the canvas match?',
            'criteria': {'true': IMAGE_PART},
        },
    },
}

REQUEST = {
    'model': MODEL,
    'state': {'question': 'Is this a useful answer?'},
    'questions': {
        'useful': {'type': 'noul', 'instructions': 'Is this a useful answer?'},
        'action': {
            'type': 'choice',
            'instructions': {'task': 'Decide whether to keep this answer.'},
            'criteria': {'keep': 'Use it', 'skip': None},
        },
        'quality': {
            'type': 'score',
            'instructions': ['Rate the answer.', {'context': 'Customer support'}],
            'criteria': ['low', 'high'],
        },
    },
}


class DecisionGateway(Gateway):
    def __init__(self, signing_algo='ed25519', kind='gateway'):
        super().__init__(signing_algo, kind)
        self.metadata = {
            'providerType': 'vllm' if kind == 'provider_tee' else 'typesafe',
            'attestationSupported': kind == 'provider_tee',
        }
        self.requests = []
        self.response_fault = None
        self.response_encoding = None
        self.decision_id = None
        self.body_id = None
        self.answers = None
        self.usage = None
        self.signature_urls = []
        self.omit_public_key = False
        self.use_alternate_signer = False
        self.alternate_key = SigningKey(bytes([9]) * 32)

    async def handle(self, request):
        if request.url.path != '/v1/systemone':
            if request.url.path.startswith('/v1/signature/'):
                self.signature_urls.append(request.url)
            response = await super().handle(request)
            if (
                request.url.path == '/v1/attestation/report'
                and 'model' in request.url.params
            ):
                body = response.json()
                # Reports may include other signing identities.
                for report in body['model_attestations']:
                    if self.omit_public_key:
                        report.pop('signing_public_key')
                if self.signing_algo == 'ed25519':
                    alternate = {**self.attestation(request.url.params['nonce'])}
                    quote = self.quotes[alternate['intel_quote']]
                    address = bytes(self.alternate_key.verify_key).hex()
                    self.quotes[alternate['intel_quote']] = replace(
                        quote,
                        report_data=bytes.fromhex(address) + quote.report_data[32:],
                    )
                    alternate.update(
                        signing_address=address,
                        report_data=self.quotes[
                            alternate['intel_quote']
                        ].report_data.hex(),
                    )
                    alternate.pop('signing_public_key')
                    body['model_attestations'].append(alternate)
                return httpx.Response(200, json=body)
            return response
        self.headers.append(request.headers)
        self.requests.append(request)
        decision_id = self.decision_id or f'systemone-{len(self.requests)}'
        if self.response_fault == 'status':
            return httpx.Response(
                503, text='private state must not be included in errors'
            )
        if json.loads(request.content)['questions'] == {}:
            return httpx.Response(422)
        body = {
            'model': MODEL,
            'answers': {
                'useful': {'type': 'noul', 'noul': 0.9},
                'action': {
                    'type': 'choice',
                    'choice': 'keep',
                    'confidence': 0.8,
                    'probabilities': {'keep': 0.8, 'skip': 0.2},
                },
                'quality': {
                    'type': 'score',
                    'score': 1,
                    'confidence': 0.9,
                    'probabilities': {'0': 0.1, '1': 0.9},
                    'legend': {'0': 'low', '1': 'high'},
                },
            },
            'usage': {'input_tokens': 5, 'output_tokens': 2},
        }
        if self.body_id is not None:
            body['id'] = self.body_id
        if self.answers is not None:
            body['answers'] = self.answers
        if self.usage is not None:
            body['usage'] = self.usage
        if self.response_fault == 'probability':
            body['answers']['useful']['noul'] = 2
        response_body = json.dumps(body).encode()
        if self.response_fault == 'json':
            response_body = b'not JSON'
        signed_text = (
            hashlib.sha256(request.content).hexdigest()
            + ':'
            + hashlib.sha256(response_body).hexdigest()
        )
        if self.kind == 'provider_tee':
            signed_text = MODEL + ':' + signed_text
        key = self.alternate_key if self.use_alternate_signer else self.key
        signature = (
            key.sign(signed_text.encode()).signature.hex()
            if self.signing_algo == 'ed25519'
            else key.sign_message(encode_defunct(text=signed_text)).signature.hex()
        )
        address = (
            bytes(key.verify_key).hex()
            if self.signing_algo == 'ed25519'
            else self.address
        )
        self.signatures[decision_id] = {
            'text': signed_text,
            'signature': signature,
            'signing_address': address,
            'signing_algo': self.signing_algo,
            'signature_kind': self.kind,
        }
        if self.response_fault == 'tamper':
            response_body = response_body.replace(b'0.9', b'0.5')
        if self.response_encoding == 'gzip':
            response_body = gzip.compress(response_body)
        elif self.response_encoding == 'br':
            response_body = brotli.compress(response_body)
        return httpx.Response(
            200,
            content=response_body,
            headers={
                **(
                    {'content-encoding': self.response_encoding}
                    if self.response_encoding
                    else {}
                ),
                'x-signature-id'
                if self.response_fault == 'id'
                else 'x-generation-id': decision_id,
            },
        )


@pytest.mark.parametrize('confidence', [{}, {'confidence': None}, {'confidence': 0.82}])
@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
async def test_box_images_preserve_bytes_and_verify_receipts(
    monkeypatch, confidence, signing_algo
):
    gateway = DecisionGateway(signing_algo)
    answer = {
        'type': 'box',
        'box': {**BOX_BOUNDS, 'future': 'preserved'},
        'future': {'preserved': True},
        **confidence,
    }
    gateway.answers = {'region': answer, 'present': {'type': 'noul', 'noul': 0.98}}
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        result = await client.systemone.create(IMAGE_REQUEST)
        assert json.loads(gateway.requests[0].content) == IMAGE_REQUEST
        assert result.data['answers']['region'] == answer
        result.data['answers']['region']['box']['top'] = 0
        verified = await client.verify_response(result.decision_id)
        assert verified.signature_kind == 'gateway'
    assert len(gateway.requests) == 1


@pytest.mark.parametrize('entrypoint', ['native', 'httpx', 'httpx2'])
@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
async def test_json_assets_preserve_references_and_receipt_bytes(
    monkeypatch, entrypoint, signing_algo
):
    request: SystemOneRequest = {
        'model': MODEL,
        'assets': {'<photo>': {'format': 'png', 'data_base64': 'ZmFrZS1pbWFnZQ=='}},
        'state': {'<photo>': ['<photo>', IMAGE_PART]},
        'questions': {
            'region': {'type': 'box', 'instructions': 'Locate <photo> — now'},
            'match': {
                'type': 'score',
                'instructions': 'Rate the match.',
                'criteria': ['Different', '<photo>'],
            },
        },
    }
    legend = {'0': 'Different', '1': '<photo>'}
    gateway = DecisionGateway(signing_algo)
    gateway.answers = {
        'region': {'type': 'box', 'box': BOX_BOUNDS},
        'match': {
            'type': 'score',
            'score': 1,
            'confidence': 0.9,
            'probabilities': {'0': 0.1, '1': 0.9},
            'legend': legend,
        },
    }
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        if entrypoint == 'native':
            body = json.dumps(request).encode()
            result = await client.systemone.create(request)
            assert result.data['answers']['match']['legend'] == legend
            receipt_id = result.decision_id
        else:
            body = (json.dumps(request, ensure_ascii=False, indent=2) + '\n').encode()
            http_client = (
                client.http_client if entrypoint == 'httpx' else client.httpx2_client
            )
            response = await http_client.post(
                client.base_url + 'systemone',
                headers={'content-type': 'application/json'},
                content=body,
            )
            assert response.json()['answers']['match']['legend'] == legend
            receipt_id = response.headers['x-generation-id']
        assert gateway.requests[0].content == body
        assert (await client.verify_response(receipt_id)).signature_kind == 'gateway'
    assert len(gateway.requests) == 1


@pytest.mark.parametrize(
    'answer',
    [
        {'type': 'box'},
        {'type': 'box', 'box': None},
        {'type': 'box', 'box': {'bottom': 1, 'left': 0, 'right': 1}},
        *[
            {'type': 'box', 'box': {**BOX_BOUNDS, 'top': top}}
            for top in (None, True, '0.31', float('inf'))
        ],
        {'type': 'box', 'box': BOX_BOUNDS, 'confidence': '0.82'},
    ],
)
async def test_malformed_box_is_not_retained_or_retried(monkeypatch, answer):
    gateway = DecisionGateway()
    gateway.answers = {'region': answer}
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(ApiError, match='api.invalid_response'):
            await client.systemone.create(IMAGE_REQUEST)
        with pytest.raises(ApiError, match='api.completion_not_found'):
            await client.verify_response('systemone-1')
    assert len(gateway.requests) == 1


async def test_clear_response_cache_allows_reusing_decision_id(monkeypatch):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        first = await client.systemone.create(REQUEST)
        await client.verify_response(first.decision_id)
        client.clear_response_cache()
        with pytest.raises(ApiError) as error:
            await client.verify_response(first.decision_id)
        assert error.value.failure.code == 'api.completion_not_found'
        next_response = await client.systemone.create(REQUEST)
        await client.verify_response(next_response.decision_id)


async def test_requires_model_public_key_before_sending_a_decision(monkeypatch):
    gateway = DecisionGateway(kind='provider_tee')
    gateway.omit_public_key = True
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(VerificationError) as raised:
            await client.systemone.create(REQUEST)
    assert raised.value.failure.code == 'e2ee.model_public_key_required'
    assert gateway.requests == []


async def test_rejects_another_preflight_verified_signer(monkeypatch):
    gateway = DecisionGateway(kind='provider_tee')
    gateway.use_alternate_signer = True
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        result = await client.systemone.create(REQUEST)
        with pytest.raises(VerificationError) as raised:
            await client.verify_response(result.decision_id)
    assert raised.value.failure.code == 'signature.signer_mismatch'
    assert gateway.requests[0].headers['x-model-pub-key'] == gateway.public_key


@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
@pytest.mark.parametrize('kind', ['gateway', 'provider_tee'])
async def test_decisions_verify_exact_bytes_with_the_selected_signer(
    monkeypatch, signing_algo, kind
):
    gateway = DecisionGateway(signing_algo, kind)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        result = await client.systemone.create(
            REQUEST,
            headers={
                'Authorization': 'Bearer ignored',
                'Content-Length': '0',
                'Content-Encoding': 'gzip',
                'Transfer-Encoding': 'chunked',
                'Trailer': 'Digest',
                'Content-MD5': 'old',
                'Digest': 'old',
                'Content-Digest': 'old',
                'Repr-Digest': 'old',
            },
        )
        assert result.decision_id == 'systemone-1'
        assert 'id' not in result.data
        result.data['answers']['useful']['noul'] = 0  # Does not alter captured bytes.
        verified, concurrent = await asyncio.gather(
            client.verify_response(result.decision_id),
            client.verify_response(result.decision_id),
        )
        assert verified.signature_kind == kind
        assert verified.id == result.decision_id
        if kind == 'provider_tee':
            assert (
                VerifiedModelCompletionResult(
                    id=verified.id,
                    signature=verified.signature,
                    attestation=verified.attestation,
                )
                == verified
            )
        assert concurrent is verified
        assert await client.verify_response(result.decision_id) is verified
    assert len(gateway.requests) == 1
    assert all(
        headers['authorization'] == 'Bearer test-key' for headers in gateway.headers
    )
    assert gateway.requests[0].headers.get('x-model-pub-key') == (
        gateway.public_key if kind == 'provider_tee' else None
    )
    assert 'x-client-pub-key' not in gateway.requests[0].headers
    assert gateway.signature_requests == 1
    sent = gateway.requests[0]
    assert json.loads(sent.content) == REQUEST
    assert sent.headers['content-length'] == str(len(sent.content))
    for name in (
        'content-encoding',
        'transfer-encoding',
        'trailer',
        'content-md5',
        'digest',
        'content-digest',
        'repr-digest',
    ):
        assert name not in sent.headers


@pytest.mark.parametrize('encoding', ['gzip', 'br'])
async def test_decoded_response_verifies_exact_json_bytes(monkeypatch, encoding):
    gateway = DecisionGateway()
    gateway.response_encoding = encoding
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        result = await client.systemone.create(
            REQUEST, headers={'Accept-Encoding': 'gzip'}
        )
        assert result.data['answers']['useful']['noul'] == 0.9
        receipt = await client.verify_response(result.decision_id)
        assert receipt.id == result.decision_id
    assert gateway.requests[0].headers['accept-encoding'] == 'identity'
    assert len(gateway.requests) == 1


async def test_receipt_can_retry_without_repeating_inference(monkeypatch):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        result = await client.systemone.create(REQUEST)
        signature = gateway.signatures[result.decision_id]
        gateway.signatures[result.decision_id] = {
            'error_code': 'pending',
            'message': 'not ready',
        }
        with pytest.raises(ApiError):
            await client.verify_response(result.decision_id)
        gateway.signatures[result.decision_id] = signature
        verified = await client.verify_response(result.decision_id)
        assert verified.signature_kind == 'gateway'
    assert len(gateway.requests) == 1
    assert gateway.signature_requests == 2


async def test_cancelled_waiter_does_not_stick_a_retryable_receipt_failure(monkeypatch):
    gateway = DecisionGateway()
    started = asyncio.Event()
    release = asyncio.Event()
    finished = asyncio.Event()
    handle = gateway.handle

    async def hold_signature(request):
        if request.url.path.startswith('/v1/signature/'):
            started.set()
            await release.wait()
            response = await handle(request)
            finished.set()
            return response
        return await handle(request)

    monkeypatch.setattr(gateway, 'handle', hold_signature)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        result = await client.systemone.create(REQUEST)
        signature = gateway.signatures[result.decision_id]
        gateway.signatures[result.decision_id] = {
            'error_code': 'pending',
            'message': 'not ready',
        }
        waiting = asyncio.create_task(client.verify_response(result.decision_id))
        await started.wait()
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        release.set()
        await finished.wait()
        gateway.signatures[result.decision_id] = signature
        verified = await client.verify_response(result.decision_id)
        assert verified.signature_kind == 'gateway'
    assert gateway.signature_requests == 2
    assert len(gateway.requests) == 1


@pytest.mark.parametrize('fault', ['status', 'id', 'probability', 'json'])
async def test_invalid_decision_response_never_replays_inference(monkeypatch, fault):
    gateway = DecisionGateway()
    gateway.response_fault = fault
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(ApiError) as raised:
            await client.systemone.create(REQUEST)
        assert not raised.value.retryable
        assert 'private state' not in str(raised.value)
    assert len(gateway.requests) == 1


@pytest.mark.parametrize('reason', ['request', 'response_body'])
async def test_decision_transport_failure_is_not_retryable(monkeypatch, reason):
    gateway = DecisionGateway()
    original = gateway.handle

    class BrokenBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            raise httpx.ReadError('connection lost')
            yield  # Make this an async iterator.

    async def respond(request):
        response = await original(request)
        if request.url.path == '/v1/systemone':
            if reason == 'request':
                raise httpx.ReadError('connection lost')
            return httpx.Response(200, headers=response.headers, stream=BrokenBody())
        return response

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(ApiError) as raised:
            await client.systemone.create(REQUEST)
        assert raised.value.failure.code == 'api.transport_failed'
        assert raised.value.failure.details == {
            'resource': 'systemone',
            'reason': reason,
        }
        assert not raised.value.retryable
    assert len(gateway.requests) == 1


@pytest.mark.parametrize(
    ('fault', 'code'), [('status', 'api.http_status'), ('id', 'api.invalid_response')]
)
async def test_response_cleanup_preserves_the_primary_error(monkeypatch, fault, code):
    gateway = DecisionGateway()
    gateway.response_fault = fault
    handle = gateway.handle
    closed = False

    class FailingCloseStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b''

        async def aclose(self):
            nonlocal closed
            closed = True
            raise httpx.ReadError('cleanup failed')

    async def respond(request):
        response = await handle(request)
        if request.url.path == '/v1/systemone':
            return httpx.Response(
                response.status_code,
                headers=response.headers,
                stream=FailingCloseStream(),
            )
        return response

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(ApiError) as raised:
            await client.systemone.create(REQUEST)
        assert raised.value.failure.code == code
    assert closed
    assert len(gateway.requests) == 1


@pytest.mark.parametrize('encoding', ['gzip', 'br'])
async def test_tampered_decision_response_fails_receipt_verification(
    monkeypatch, encoding
):
    gateway = DecisionGateway()
    gateway.response_encoding = encoding
    gateway.response_fault = 'tamper'
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        result = await client.systemone.create(REQUEST)
        for _ in range(2):
            with pytest.raises(VerificationError):
                await client.verify_response(result.decision_id)
    assert gateway.signature_requests == 1


@pytest.mark.parametrize(
    ('options', 'body'),
    [
        ({'e2ee': True}, REQUEST),
        ({'e2ee': False, 'ohttp': True}, REQUEST),
        ({'e2ee': False}, {**REQUEST, 'stream': True}),
    ],
)
async def test_unsupported_decision_modes_fail_before_preflight(
    monkeypatch, options, body
):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    async with gateway.client(**options) as client:
        with pytest.raises(ApiError) as raised:
            await client.systemone.create(body)
        assert raised.value.failure.code == 'api.invalid_input'
    assert gateway.gateway_requests == 0
    assert gateway.requests == []


@pytest.mark.parametrize(
    'model_fields',
    [{}, {'model': ''}, {'model': None}, {'model': 1}, {'model': '.'}, {'model': '..'}],
)
async def test_invalid_decision_model_fails_before_preflight(monkeypatch, model_fields):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    request = {key: value for key, value in REQUEST.items() if key != 'model'}
    request.update(model_fields)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(ApiError) as raised:
            await client.systemone.create(request)
        assert raised.value.failure.code == 'api.invalid_input'
        assert raised.value.failure.details['field'] == 'model'
    assert gateway.gateway_requests == 0
    assert gateway.model_requests == []
    assert gateway.requests == []


@pytest.mark.parametrize(
    'headers',
    [
        {'x-tenant': 'invalid\nvalue'},
        {'invalid name': 'value'},
        {'x-tenant': '雪'},
        {'x-tenant': ' leading'},
        {'x-tenant': 'trailing '},
        {'x-tenant': '\tleading'},
        {'x-tenant': 'trailing\t'},
    ],
)
async def test_invalid_decision_headers_fail_before_preflight(monkeypatch, headers):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(ApiError) as raised:
            await client.systemone.create(REQUEST, headers=headers)
        assert raised.value.failure.code == 'api.invalid_input'
        assert raised.value.failure.details['field'] == 'headers'
    assert gateway.gateway_requests == 0
    assert gateway.model_requests == []
    assert gateway.requests == []


@pytest.mark.parametrize(
    'decision_id,encoded_id',
    [
        ('jev/run:1?variant=2#decision', 'jev%2Frun%3A1%3Fvariant%3D2%23decision'),
        ('.', '%2E'),
        ('..', '%2E%2E'),
    ],
)
async def test_generation_header_is_the_opaque_lookup_id_not_the_body_id(
    monkeypatch, decision_id, encoded_id
):
    gateway = DecisionGateway()
    gateway.decision_id = decision_id
    gateway.body_id = 'provider-body-id'
    gateway.install(monkeypatch)

    async with gateway.client(e2ee=False) as client:
        result = await client.systemone.create(REQUEST)
        assert result.decision_id == gateway.decision_id
        assert result.data['id'] == 'provider-body-id'
        verified = await client.verify_response(result.decision_id)
        assert verified.id == result.decision_id

    assert gateway.signature_urls[0].raw_path == (
        f'/v1/signature/{encoded_id}?signing_algo=ed25519'.encode()
    )


async def test_request_business_validation_is_left_to_the_server(monkeypatch):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(ApiError) as raised:
            await client.systemone.create({**REQUEST, 'questions': {}})
        assert raised.value.failure.code == 'api.http_status'
        assert raised.value.failure.details['status'] == 422
    assert len(gateway.requests) == 1


@pytest.mark.parametrize('systemone_first', [False, True])
async def test_chat_and_decisions_share_cached_sessions(monkeypatch, systemone_first):
    gateway = DecisionGateway(kind='provider_tee')
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:

        async def chat():
            completion = await client.chat.completions.create(
                model=MODEL, messages=MESSAGES
            )
            await client.verify_response(completion.id)

        async def decision():
            result = await client.systemone.create(REQUEST)
            await client.verify_response(result.decision_id)

        calls = [decision, chat] if systemone_first else [chat, decision]
        for call in calls * 2:
            await call()
    assert gateway.gateway_requests == 1
    assert gateway.model_requests == [MODEL]
    assert all(
        request.headers['x-model-pub-key'] == gateway.public_key
        for request in [*gateway.completion_requests, *gateway.requests]
    )
    assert len(gateway.completion_requests) == 2
    assert len(gateway.requests) == 2


async def test_decision_response_expires_without_repeating_inference(monkeypatch):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False, response_cache_time_to_live_ms=1) as client:
        result = await client.systemone.create(REQUEST)
        await asyncio.sleep(0.01)
        with pytest.raises(ApiError) as raised:
            await client.verify_response(result.decision_id)
        assert raised.value.failure.code == 'api.completion_not_found'
    assert len(gateway.requests) == 1
    assert gateway.signature_requests == 0


async def test_closing_after_a_decision_does_not_leave_response_expiry_running(
    monkeypatch,
):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    client = gateway.client(e2ee=False)
    result = await client.systemone.create(REQUEST)
    record = client._responses[result.decision_id]
    await client.aclose()
    # Future completion callbacks queued by create() must not retain closed data.
    await asyncio.sleep(0)
    assert client._responses == {}
    assert record.expiry is None or record.expiry.cancelled()


async def test_a_decision_body_finishing_after_close_cannot_repopulate_the_cache(
    monkeypatch,
):
    gateway = DecisionGateway()
    started = asyncio.Event()
    release = asyncio.Event()
    handle = gateway.handle

    async def respond(request):
        response = await handle(request)
        if request.url.path != '/v1/systemone':
            return response

        class PendingBody(httpx.AsyncByteStream):
            async def __aiter__(self):
                started.set()
                await release.wait()
                yield response.content

        return httpx.Response(200, headers=response.headers, stream=PendingBody())

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    client = gateway.client(e2ee=False)
    pending = asyncio.create_task(client.systemone.create(REQUEST))
    await started.wait()
    await client.aclose()
    release.set()
    with pytest.raises(RuntimeError, match='InferenceClient is closed'):
        await pending
    assert client._responses == {}


@pytest.mark.parametrize('kind', ['gateway', 'provider_tee'])
async def test_decision_preflight_rejects_an_incompatible_gateway_signer(
    monkeypatch,
    kind,
):
    gateway = DecisionGateway(kind=kind)
    gateway.install(monkeypatch)
    # The endpoint ignores the requested algorithm; stop before sending a decision.
    async with gateway.client(e2ee=False, signing_algo='ecdsa') as client:
        with pytest.raises(VerificationError) as raised:
            await client.systemone.create(REQUEST)
        assert raised.value.failure.code == 'signature.signer_mismatch'
    assert gateway.requests == []
    assert gateway.signature_requests == 0


async def test_decision_model_requests_wait_for_gateway_verification(monkeypatch):
    gateway = DecisionGateway(kind='provider_tee')
    gateway.install(monkeypatch)
    release_gateway = asyncio.Event()
    gateway_started = asyncio.Event()
    model_verified = asyncio.Event()

    async def verify_gateway_quote(quote):
        gateway_started.set()
        await release_gateway.wait()
        return gateway.quotes[quote]

    async def verify_model_deployment(_deployment):
        model_verified.set()

    async with gateway.client(
        e2ee=False,
        gateway_verification=GatewayVerificationOptions(
            verifiers=AttestationVerifiers(tdx_quote=verify_gateway_quote)
        ),
        model_verification=ModelVerificationOptions(
            verifiers=ModelAttestationVerifiers(
                tdx_quote=gateway.quotes.__getitem__,
                deployment=verify_model_deployment,
            )
        ),
    ) as client:
        decision = asyncio.create_task(client.systemone.create(REQUEST))
        async with asyncio.timeout(1):
            await gateway_started.wait()
        assert gateway.model_requests == []
        assert gateway.headers == []
        assert gateway.requests == []
        assert not decision.done()
        release_gateway.set()
        result = await decision
        assert model_verified.is_set()
        await client.verify_response(result.decision_id)

    assert gateway.gateway_requests == 1
    assert gateway.model_requests == [MODEL]
    assert len(gateway.requests) == 1


async def test_cancelling_one_decision_does_not_cancel_shared_preflight(monkeypatch):
    gateway = DecisionGateway(kind='provider_tee')
    started = asyncio.Event()
    release = asyncio.Event()
    handle = gateway.handle

    async def hold_preflight(request):
        if (
            request.url.path == '/v1/attestation/report'
            and 'model' not in request.url.params
        ):
            started.set()
            await release.wait()
        return await handle(request)

    monkeypatch.setattr(gateway, 'handle', hold_preflight)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        cancelled = asyncio.create_task(client.systemone.create(REQUEST))
        await started.wait()
        continuing = asyncio.create_task(client.systemone.create(REQUEST))
        await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        release.set()
        result = await continuing
        await client.verify_response(result.decision_id)
    assert gateway.gateway_requests == 1
    assert gateway.model_requests == [MODEL]
    assert len(gateway.requests) == 1


@pytest.mark.parametrize(
    'header',
    ['content-encoding', 'content-md5', 'digest', 'content-digest', 'repr-digest'],
)
async def test_native_decisions_strip_configured_body_headers(monkeypatch, header):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    value = 'gzip' if header == 'content-encoding' else 'stale'

    async with gateway.client(e2ee=False, headers={header: value}) as client:
        result = await client.systemone.create(REQUEST)
        await client.verify_response(result.decision_id)

    assert header not in gateway.requests[0].headers
