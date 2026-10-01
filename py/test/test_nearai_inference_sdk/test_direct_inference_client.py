import httpx
import pytest
from openai import AsyncOpenAI

from nearai_inference_sdk import (
    DirectAttestationVerificationResult,
    DirectInferenceClient,
    DirectModelVerificationOptions,
    ModelAttestationVerifiers,
    ModelVerificationOptions,
    VerificationError,
)
from nearai_inference_sdk.core import direct_inference_client

from .ohttp_fixtures import OhttpGateway
from .test_inference_client import BASE_URL, MESSAGES, MODEL, Gateway


class DirectEndpoint(Gateway):
    def __init__(self, signing_algo='ed25519'):
        super().__init__(signing_algo)
        self.ohttp_gateway = OhttpGateway(handler=self.handle_chat)
        self.bad_sibling = False

    async def handle_chat(self, request):
        return await super().handle(request)

    async def handle(self, request):
        if request.url.path == '/ohttp':
            return await self.ohttp_gateway.handle(request)
        if request.url.path == '/v1/attestation/report':
            assert 'model' not in request.url.params
            assert request.url.params['include_tls_fingerprint'] == 'false'
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
        monkeypatch.setattr(
            DirectInferenceClient,
            '_create_direct_client',
            lambda _client, _fingerprints: httpx.AsyncClient(
                transport=httpx.MockTransport(self.handle)
            ),
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
    monkeypatch, signing_algo, e2ee, ohttp
):
    endpoint = DirectEndpoint(signing_algo)
    endpoint.install(monkeypatch)
    now = 1_700_000_000
    monkeypatch.setattr(direct_inference_client, 'time', lambda: now)
    async with endpoint.client(e2ee=e2ee, ohttp=ohttp) as client:
        attestations = await client.verify(MODEL)
        assert isinstance(attestations, DirectAttestationVerificationResult)
        assert len(attestations.attestations) == 2
        assert attestations.serving_attestation is attestations.attestations[0]
        assert attestations.tls_binding.kind == 'none'
        assert attestations.spki_fingerprints == ()
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
            api_key='unused', base_url=BASE_URL, http_client=client.http_client
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


async def test_serving_deployment_policy_blocks_chat(monkeypatch):
    endpoint = DirectEndpoint()
    endpoint.install(monkeypatch)
    checked = []

    def reject(deployment):
        checked.append(deployment)
        raise ValueError('Unapproved serving deployment')

    async with DirectInferenceClient(
        BASE_URL,
        model_verification=DirectModelVerificationOptions(
            verifiers=ModelAttestationVerifiers(tdx_quote=endpoint.quotes.__getitem__),
            serving_deployment=reject,
        ),
    ) as client:
        with pytest.raises(ValueError, match='Unapproved serving deployment'):
            await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
    assert len(checked) == 1
    assert endpoint.completion_requests == []
