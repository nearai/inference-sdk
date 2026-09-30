"""Decision requests preserve the public protocol and verify exact signed bytes."""

import asyncio
import hashlib
import json
from dataclasses import replace

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
    VerificationError,
)
from nearai_inference_sdk.core import inference_client

from .test_inference_client import MESSAGES, MODEL, Gateway

REQUEST = {
    'model': MODEL,
    'state': {'question': 'Is this a useful answer?'},
    'questions': {
        'useful': {'type': 'noul'},
        'action': {'type': 'choice', 'criteria': {'keep': 'Use it', 'skip': None}},
        'quality': {'type': 'score', 'criteria': ['low', 'high']},
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
        self.decision_id = None
        self.body_id = None
        self.answers = None
        self.usage = None
        self.signature_urls = []
        self.omit_public_key = True
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
                # A decision service need not provide a Chat encryption key.
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
        key = (
            self.alternate_key
            if self.kind == 'provider_tee' and self.signing_algo == 'ed25519'
            else self.key
        )
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
        return httpx.Response(
            200,
            content=response_body,
            headers={
                'x-signature-id'
                if self.response_fault == 'id'
                else 'x-generation-id': decision_id,
            },
        )


@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
@pytest.mark.parametrize('kind', ['gateway', 'provider_tee'])
async def test_decisions_verify_exact_bytes_with_the_actual_serving_signer(
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
        assert concurrent is verified
        assert await client.verify_response(result.decision_id) is verified
    assert len(gateway.requests) == 1
    assert all(
        headers['authorization'] == 'Bearer test-key' for headers in gateway.headers
    )
    assert 'x-model-pub-key' not in gateway.requests[0].headers
    assert gateway.signature_requests == 1
    sent = gateway.requests[0]
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


async def test_tampered_decision_response_fails_receipt_verification(monkeypatch):
    gateway = DecisionGateway()
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
    'model_fields', [{}, {'model': ''}, {'model': None}, {'model': 1}]
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
    [{'x-tenant': 'invalid\nvalue'}, {'invalid name': 'value'}, {'x-tenant': '雪'}],
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


async def test_generation_header_is_the_opaque_lookup_id_not_the_body_id(monkeypatch):
    gateway = DecisionGateway()
    gateway.decision_id = 'jev/run:1?variant=2#decision'
    gateway.body_id = 'provider-body-id'
    gateway.install(monkeypatch)

    async with gateway.client(e2ee=False) as client:
        result = await client.systemone.create(REQUEST)
        assert result.decision_id == gateway.decision_id
        assert result.data['id'] == 'provider-body-id'
        verified = await client.verify_response(result.decision_id)
        assert verified.id == result.decision_id

    assert gateway.signature_urls[0].raw_path == (
        b'/v1/signature/jev%2Frun%3A1%3Fvariant%3D2%23decision?signing_algo=ed25519'
    )


async def test_question_names_and_choice_labels_are_preserved(monkeypatch):
    gateway = DecisionGateway()
    gateway.answers = {
        'constructor': {
            'type': 'choice',
            'choice': 'prototype',
            'confidence': 1,
            'probabilities': {'prototype': 1, '__proto__': 0},
        },
        '__proto__': {'type': 'noul', 'noul': 0.9},
    }
    gateway.usage = {'input_tokens': 2147483648, 'output_tokens': 1}
    gateway.install(monkeypatch)

    async with gateway.client(e2ee=False) as client:
        result = await client.systemone.create(
            {
                **REQUEST,
                'questions': {
                    'constructor': {
                        'type': 'choice',
                        'criteria': {'prototype': 'First', '__proto__': 'Second'},
                    },
                    '__proto__': {'type': 'noul'},
                },
            }
        )
        assert result.data['answers'] == gateway.answers
        assert result.data['usage'] == gateway.usage
        await client.verify_response(result.decision_id)


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
async def test_chat_and_decisions_keep_separate_cached_sessions(
    monkeypatch, systemone_first
):
    gateway = DecisionGateway(kind='provider_tee')
    gateway.omit_public_key = False
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
    assert gateway.gateway_requests == 2
    assert gateway.model_requests == [MODEL, MODEL]
    assert all(
        request.headers['x-model-pub-key'] == gateway.public_key
        for request in gateway.completion_requests
    )
    assert len(gateway.completion_requests) == 2
    assert len(gateway.requests) == 2


@pytest.mark.parametrize('ttl_ms', [0, 1000])
async def test_decision_attestation_cache_honors_expiry_and_disabling(
    monkeypatch, ttl_ms
):
    gateway = DecisionGateway(kind='provider_tee')
    gateway.install(monkeypatch)
    now = 0
    monkeypatch.setattr(inference_client, 'monotonic', lambda: now)
    async with gateway.client(
        e2ee=False, attestation_cache_time_to_live_ms=ttl_ms
    ) as client:
        for instant in [0, 0.5, 2]:
            now = instant
            result = await client.systemone.create(REQUEST)
            await client.verify_response(result.decision_id)
    assert gateway.gateway_requests == (3 if ttl_ms == 0 else 2)
    assert len(gateway.model_requests) == gateway.gateway_requests


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


async def test_decision_preflight_requires_the_configured_signing_algorithm(
    monkeypatch,
):
    gateway = DecisionGateway(kind='provider_tee')
    gateway.install(monkeypatch)
    # The endpoint ignores the requested algorithm; stop before sending a decision.
    async with gateway.client(e2ee=False, signing_algo='ecdsa') as client:
        with pytest.raises(VerificationError) as raised:
            await client.systemone.create(REQUEST)
        assert raised.value.failure.code == 'signature.signer_mismatch'
    assert gateway.requests == []
    assert gateway.signature_requests == 0


async def test_decision_preflight_is_concurrent_but_blocks_inference(monkeypatch):
    gateway = DecisionGateway(kind='provider_tee')
    gateway.install(monkeypatch)
    release_gateway = asyncio.Event()
    model_verified = asyncio.Event()

    async def verify_gateway_quote(quote):
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
            await model_verified.wait()
        assert gateway.requests == []
        assert not decision.done()
        release_gateway.set()
        result = await decision
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
