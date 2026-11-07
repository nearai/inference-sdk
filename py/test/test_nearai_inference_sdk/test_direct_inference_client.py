import hashlib
import json
from dataclasses import replace

import httpx
import pytest
from openai import AsyncOpenAI

from nearai_inference_sdk import (
    DirectAttestationVerificationResult,
    DirectInferenceClient,
    ModelAttestationVerifiers,
    ModelVerificationOptions,
    VerificationError,
)
from nearai_inference_sdk.core import direct_inference_client

from .ohttp_fixtures import OhttpGateway
from .test_inference_client import BASE_URL, MESSAGES, MODEL, TLS_FINGERPRINT, Gateway


def bind_tls_report(endpoint, report, fingerprint):
    quote = replace(
        endpoint.quotes[report['intel_quote']],
        report_data=hashlib.sha256(
            bytes.fromhex(endpoint.address.removeprefix('0x'))
            + bytes.fromhex(fingerprint)
        ).digest()
        + bytes.fromhex(report['request_nonce']),
    )
    endpoint.quotes[report['intel_quote']] = quote
    report['report_data'] = quote.report_data.hex()
    report['tls_cert_fingerprint'] = fingerprint
    return report


class DirectEndpoint(Gateway):
    def __init__(self, signing_algo='ed25519'):
        super().__init__(signing_algo)
        self.ohttp_gateway = OhttpGateway(handler=self.handle_chat)
        self.bad_sibling = False
        self.pinned_groups = []

    async def handle_chat(self, request):
        return await super().handle(request)

    async def handle(self, request):
        if request.url.path == '/ohttp':
            return await self.ohttp_gateway.handle(request)
        if request.url.path == '/v1/attestation/report':
            assert 'model' not in request.url.params
            include_tls = request.url.params['include_tls_fingerprint'] == 'true'
            self.model_requests.append('direct')
            root = {
                **self.attestation(request.url.params['nonce']),
                'model_name': MODEL,
            }
            self.bad_quote = self.bad_sibling
            sibling = {
                **self.attestation(request.url.params['nonce']),
                'model_name': MODEL,
            }
            body = {**root, 'all_attestations': [root, sibling]}
            if include_tls:
                for report, fingerprint in zip(
                    (root, sibling), (TLS_FINGERPRINT, '22' * 32), strict=True
                ):
                    bind_tls_report(self, report, fingerprint)
                body.update(root)
            if self.signing_algo == 'ed25519':
                config = self.ohttp_gateway.key_config
                body['ohttp_attestation'] = {
                    'signing_algo': 'ed25519',
                    'signing_key': self.public_key,
                    'key_config': config.hex(),
                    'signature': self.key.sign(config).signature.hex(),
                }
            return httpx.Response(200, json=body)
        response = await super().handle(request)
        if request.url.path.startswith('/v1/signature/'):
            signature = response.json()
            signature.pop('signature_kind')
            return httpx.Response(200, json=signature)
        return response

    def install(self, monkeypatch):
        super().install(monkeypatch)

        def create_client(_client, fingerprints):
            self.pinned_groups.append(fingerprints)
            return httpx.AsyncClient(transport=httpx.MockTransport(self.handle))

        monkeypatch.setattr(
            DirectInferenceClient,
            '_create_direct_client',
            create_client,
        )

    def client(self, **options):
        return DirectInferenceClient(
            BASE_URL,
            signing_algo=self.signing_algo,
            model_verification=ModelVerificationOptions(
                verifiers=ModelAttestationVerifiers(tdx_quote=self.quotes.__getitem__)
            ),
            **options,
        )


@pytest.mark.parametrize('adapter_name', ['http_client', 'httpx2_client'])
@pytest.mark.parametrize(
    ('signing_algo', 'e2ee', 'ohttp'),
    [
        ('ed25519', False, False),
        ('ed25519', True, False),
        ('ecdsa', True, False),
        ('ed25519', True, True),
    ],
)
async def test_direct_chat_and_stream_verify_the_selected_signer_group(
    monkeypatch, signing_algo, e2ee, ohttp, adapter_name
):
    endpoint = DirectEndpoint(signing_algo)
    endpoint.install(monkeypatch)
    now = 1_700_000_000
    monkeypatch.setattr(direct_inference_client, 'time', lambda: now)
    options = {'ohttp': ohttp}
    if e2ee:
        options['e2ee'] = True
    async with endpoint.client(**options) as client:
        attestations = await client.verify(MODEL)
        assert isinstance(attestations, DirectAttestationVerificationResult)
        assert len(attestations.attestations) == 2
        assert attestations.serving_attestation is attestations.attestations[0]
        assert attestations.tls_binding.kind == 'attested'
        assert attestations.spki_fingerprints == (TLS_FINGERPRINT, '22' * 32)
        assert endpoint.pinned_groups == [attestations.spki_fingerprints]
        now += 1
        cached = await client.verify(MODEL)
        assert cached is attestations
        assert cached.verified_at == 1_700_000_000_000
        assert endpoint.completion_requests == []
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        assert completion.choices[0].message.content == 'Hello back'
        result = await client.verify_response(completion.id)
        assert result.id == completion.id
        assert result.signature_kind == 'provider_tee'
        assert result.attestations == attestations.attestations

        openai = AsyncOpenAI(
            api_key='unused',
            base_url=BASE_URL,
            http_client=getattr(client, adapter_name),
        )
        stream = await openai.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        chunks = [chunk async for chunk in stream]
        assert chunks[0].choices[0].delta.content == 'Hello back'
        result = await client.verify_response(chunks[0].id)
        assert len(result.attestations) == 2
    assert endpoint.gateway_requests == 0
    assert endpoint.model_requests == ['direct']
    assert endpoint.plaintexts == ['Hello', 'Hello']
    for request in endpoint.completion_requests:
        assert ('x-client-pub-key' in request.headers) == e2ee
        if not e2ee:
            assert json.loads(request.content)['messages'] == MESSAGES


async def test_direct_preflight_rejects_an_invalid_sibling_before_chat(monkeypatch):
    endpoint = DirectEndpoint()
    endpoint.bad_sibling = True
    endpoint.install(monkeypatch)
    async with endpoint.client() as client:
        with pytest.raises(VerificationError) as raised:
            await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
        assert raised.value.failure.code == 'policy.debug_enabled'
    assert endpoint.completion_requests == []


async def test_deployment_verifier_blocks_chat(monkeypatch):
    endpoint = DirectEndpoint()
    endpoint.install(monkeypatch)

    def reject(_deployment):
        raise ValueError('Unapproved deployment')

    async with DirectInferenceClient(
        BASE_URL,
        model_verification=ModelVerificationOptions(
            verifiers=ModelAttestationVerifiers(
                tdx_quote=endpoint.quotes.__getitem__, deployment=reject
            ),
        ),
    ) as client:
        with pytest.raises(VerificationError) as raised:
            await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
    assert raised.value.failure.code == 'provenance.verification_failed'
    assert endpoint.completion_requests == []


@pytest.mark.parametrize('e2ee', [False, True], ids=['plaintext', 'encrypted'])
@pytest.mark.parametrize(
    'alternate_signer', [False, True], ids=['selected-signer', 'other-verified-signer']
)
async def test_direct_ohttp_selects_serving_group_when_serving_is_not_first(
    monkeypatch, e2ee, alternate_signer
):
    endpoint = DirectEndpoint()
    other = Gateway(seed=bytes([8]) * 32)
    other.quotes = endpoint.quotes
    original_handle = endpoint.handle

    async def handle(request):
        response = await original_handle(request)
        if request.url.path == '/v1/attestation/report':
            body = response.json()
            unrelated = {
                **other.attestation(request.url.params['nonce']),
                'model_name': MODEL,
            }
            bind_tls_report(other, unrelated, '33' * 32)
            body['all_attestations'].insert(0, unrelated)
            return httpx.Response(200, json=body)
        if alternate_signer and request.url.path.startswith('/v1/signature/'):
            signature = response.json()
            signature['signing_address'] = other.address
            signature['signature'] = other.key.sign(
                signature['text'].encode()
            ).signature.hex()
            return httpx.Response(200, json=signature)
        return response

    monkeypatch.setattr(endpoint, 'handle', handle)
    endpoint.install(monkeypatch)
    async with endpoint.client(e2ee=e2ee, ohttp=True) as client:
        preflight = await client.verify(MODEL)
        assert len(preflight.attestations) == 3
        assert preflight.serving_attestation is preflight.attestations[1]
        assert preflight.attestations[0].signer.signing_address == other.address
        assert endpoint.pinned_groups == [(TLS_FINGERPRINT, '22' * 32)]
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        assert completion.choices[0].message.content == 'Hello back'
        if alternate_signer:
            with pytest.raises(VerificationError, match='signature.signer_mismatch'):
                await client.verify_response(completion.id)
        else:
            receipt = await client.verify_response(completion.id)
            assert receipt.attestations == preflight.attestations[1:]
            assert all(
                actual is expected
                for actual, expected in zip(
                    receipt.attestations, preflight.attestations[1:], strict=True
                )
            )
    assert (
        endpoint.completion_requests[0].headers['x-model-pub-key']
        == endpoint.public_key
    )
    assert len(endpoint.completion_requests) == 1
    assert endpoint.model_requests == ['direct']
    assert endpoint.signature_requests == 1


async def test_direct_ohttp_never_uses_another_signers_key_when_serving_key_is_missing(
    monkeypatch,
):
    endpoint = DirectEndpoint()
    other = Gateway(seed=bytes([8]) * 32)
    other.quotes = endpoint.quotes
    original_handle = endpoint.handle

    async def handle(request):
        response = await original_handle(request)
        if request.url.path != '/v1/attestation/report':
            return response
        body = response.json()
        body.pop('signing_public_key')
        for report in body['all_attestations']:
            report.pop('signing_public_key')
        body['all_attestations'].insert(
            0,
            bind_tls_report(
                other,
                {**other.attestation(request.url.params['nonce']), 'model_name': MODEL},
                '33' * 32,
            ),
        )
        return httpx.Response(200, json=body)

    monkeypatch.setattr(endpoint, 'handle', handle)
    endpoint.install(monkeypatch)
    async with endpoint.client(ohttp=True) as client:
        with pytest.raises(VerificationError, match='e2ee.model_public_key_required'):
            await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
    assert endpoint.completion_requests == []
    assert endpoint.signature_requests == 0
