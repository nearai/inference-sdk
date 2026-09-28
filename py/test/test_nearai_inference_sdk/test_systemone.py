"""Decision requests preserve the public protocol and verify exact signed bytes."""

import hashlib
import json
from dataclasses import replace

import httpx
import pytest
from eth_account.messages import encode_defunct
from nacl.signing import SigningKey

from nearai_inference_sdk import ApiError, VerificationError

from .test_inference_client import MODEL, Gateway


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
        self.signature_id = 'systemone-receipt'
        self.alternate_key = SigningKey(bytes([9]) * 32)

    async def handle(self, request):
        if request.url.path != '/v1/systemone':
            response = await super().handle(request)
            if (
                request.url.path == '/v1/attestation/report'
                and 'model' in request.url.params
            ):
                body = response.json()
                # A decision service need not provide a Chat encryption key.
                for report in body['model_attestations']:
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
        if self.response_fault == 'status':
            return httpx.Response(
                503, text='private state must not be included in errors'
            )
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
        if self.response_fault == 'answers':
            del body['answers']['useful']
        if self.response_fault == 'probability':
            body['answers']['useful']['noul'] = 2
        if self.response_fault == 'choice':
            body['answers']['action']['choice'] = 'unknown'
        if self.response_fault == 'score':
            body['answers']['quality']['legend'] = {}
        if self.response_fault == 'usage':
            body['usage']['input_tokens'] = 2147483647
        response_body = json.dumps(body).encode()
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
        self.signatures[self.signature_id] = {
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
                'x-signature-id': 'bad/id'
                if self.response_fault == 'id'
                else self.signature_id,
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
            REQUEST, headers={'Authorization': 'Bearer ignored'}
        )
        assert result.signature_id == 'systemone-receipt'
        assert 'id' not in result.data
        result.data['answers']['useful']['noul'] = 0  # Does not alter captured bytes.
        verified = await result.verify()
        assert verified.signature_kind == kind
        assert await result.verify() is verified
    assert len(gateway.requests) == 1
    assert all(
        headers['authorization'] == 'Bearer test-key' for headers in gateway.headers
    )
    assert 'x-model-pub-key' not in gateway.requests[0].headers


async def test_receipt_can_retry_without_repeating_inference(monkeypatch):
    gateway = DecisionGateway()
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        result = await client.systemone.create(REQUEST)
        signature = gateway.signatures[gateway.signature_id]
        gateway.signatures[gateway.signature_id] = {
            'error_code': 'pending',
            'message': 'not ready',
        }
        with pytest.raises(ApiError):
            await result.verify()
        gateway.signatures[gateway.signature_id] = signature
        assert (await result.verify()).signature_kind == 'gateway'
    assert len(gateway.requests) == 1
    assert gateway.signature_requests == 2


@pytest.mark.parametrize(
    'fault', ['status', 'id', 'answers', 'probability', 'choice', 'score', 'usage']
)
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
        with pytest.raises(VerificationError):
            await result.verify()


@pytest.mark.parametrize(
    ('options', 'body'),
    [
        ({'e2ee': True}, REQUEST),
        ({'e2ee': False, 'ohttp': True}, REQUEST),
        ({'e2ee': False}, {**REQUEST, 'stream': True}),
        ({'e2ee': False}, {**REQUEST, 'questions': {}}),
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
