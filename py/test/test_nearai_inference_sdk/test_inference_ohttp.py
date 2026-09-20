"""Exercise OHTTP through the public Chat client and real receipt signatures."""

from __future__ import annotations

import hashlib

import httpx
import pytest
from nacl.signing import SigningKey

from nearai_inference_sdk import ApiError, InferenceClient, VerificationError

from .ohttp_fixtures import OhttpGateway
from .test_inference_client import BASE_URL, MESSAGES, MODEL, Gateway


class _RecordedStream(httpx.AsyncByteStream):
    def __init__(self, stream: httpx.AsyncByteStream, chunks: list[bytes]):
        self.stream = stream
        self.chunks = chunks

    async def __aiter__(self):
        async for chunk in self.stream:
            self.chunks.append(chunk)
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class ObliviousGateway(Gateway):
    """Wrap the signed Gateway fixture with the real OHTTP server fixture."""

    def __init__(self, kind: str = 'provider_tee'):
        super().__init__(kind=kind)
        self.ohttp_gateway = OhttpGateway(handler=self.handle_inner)
        self.outer_requests: list[httpx.Request] = []
        self.transport_paths: list[str] = []
        self.response_chunks: list[list[bytes]] = []
        self.proof_failure: str | None = None

    async def handle_inner(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == '/v1/chat/completions'
        response = await super().handle(request)
        chunks: list[bytes] = []
        self.response_chunks.append(chunks)
        response.stream = _RecordedStream(response.stream, chunks)
        return response

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.transport_paths.append(request.url.path)
        if request.url.path == '/ohttp':
            self.outer_requests.append(request)
            return await self.ohttp_gateway.handle(request)
        response = await super().handle(request)
        if (
            request.url.path == '/v1/attestation/report'
            and 'model' not in request.url.params
        ):
            if self.proof_failure == 'missing':
                return response
            key = (
                SigningKey(bytes([9]) * 32)
                if self.proof_failure == 'signer'
                else self.key
            )
            config = self.ohttp_gateway.key_config
            payload = response.json()
            payload['ohttp_attestation'] = {
                'signing_algo': 'ed25519',
                'signing_key': bytes(key.verify_key).hex(),
                'key_config': config.hex(),
                'signature': (
                    '00' * 64
                    if self.proof_failure == 'signature'
                    else key.sign(config).signature.hex()
                ),
            }
            return httpx.Response(200, json=payload)
        return response

    def client(self, **options) -> InferenceClient:
        return super().client(ohttp=True, **options)


@pytest.mark.parametrize('e2ee', [False, True])
@pytest.mark.parametrize('kind', ['provider_tee', 'gateway'])
async def test_ohttp_json_and_sse_verify_the_exact_inner_bytes(monkeypatch, e2ee, kind):
    gateway = ObliviousGateway(kind)
    gateway.install(monkeypatch)

    async with gateway.client(e2ee=e2ee) as client:
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        assert completion.choices[0].message.content == 'Hello back'
        first = await client.verify_response(completion.id)

        stream = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        chunks = [chunk async for chunk in stream]
        assert (
            ''.join(chunk.choices[0].delta.content or '' for chunk in chunks)
            == 'Hello back'
        )
        second = await client.verify_response(chunks[0].id)

        for receipt, request, response_chunks in zip(
            (first, second),
            gateway.completion_requests,
            gateway.response_chunks,
            strict=True,
        ):
            signed_text = ':'.join(
                (
                    hashlib.sha256(request.content).hexdigest(),
                    hashlib.sha256(b''.join(response_chunks)).hexdigest(),
                )
            )
            if kind == 'provider_tee':
                signed_text = f'{MODEL}:{signed_text}'
            assert receipt.signature_kind == kind
            assert receipt.signature.signed_text == signed_text

    assert gateway.plaintexts == ['Hello', 'Hello']
    assert gateway.gateway_requests == 1
    assert gateway.model_requests == [MODEL]
    assert gateway.signature_requests == 2
    assert gateway.transport_paths == [
        '/v1/attestation/report',
        '/v1/attestation/report',
        '/ohttp',
        '/v1/signature/chatcmpl-1',
        '/ohttp',
        '/v1/signature/chatcmpl-2',
    ]
    assert all(b'Hello' not in request.content for request in gateway.outer_requests)
    assert all(
        ('x-client-pub-key' in request.headers) == e2ee
        for request in gateway.completion_requests
    )
    assert all(
        (b'Hello' not in request.content) == e2ee
        for request in gateway.completion_requests
    )


@pytest.mark.parametrize(
    ('failure', 'code'),
    [
        ('missing', 'ohttp.attestation_required'),
        ('signer', 'ohttp.signer_mismatch'),
        ('signature', 'ohttp.signature_invalid'),
    ],
)
async def test_untrusted_ohttp_proof_blocks_inference(monkeypatch, failure, code):
    gateway = ObliviousGateway()
    gateway.proof_failure = failure
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        request = httpx.Request(
            'POST',
            BASE_URL + 'chat/completions',
            json={'model': MODEL, 'messages': MESSAGES},
        )
        with pytest.raises(VerificationError) as raised:
            await client.send(request)

    assert raised.value.failure.code == code
    assert gateway.outer_requests == []
    assert gateway.completion_requests == []
    assert gateway.signature_requests == 0


@pytest.mark.parametrize('e2ee', [False, True])
async def test_missing_ohttp_final_tag_after_done_prevents_receipt_verification(
    monkeypatch, e2ee
):
    gateway = ObliviousGateway()
    gateway.ohttp_gateway.truncate_final_response = True
    gateway.install(monkeypatch)

    async with gateway.client(e2ee=e2ee) as client:
        stream = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        chunks = [chunk async for chunk in stream]
        assert chunks[0].choices[0].delta.content == 'Hello back'
        with pytest.raises(VerificationError) as raised:
            await client.verify_response(chunks[0].id)

    assert raised.value.failure.code == 'ohttp.decryption_failed'
    assert gateway.signature_requests == 0


def test_ohttp_rejects_ecdsa_signing_before_creating_clients():
    with pytest.raises(ApiError) as raised:
        InferenceClient('test-key', ohttp=True, signing_algo='ecdsa')

    assert raised.value.failure.code == 'api.invalid_input'
    assert raised.value.failure.details['field'] == 'signing_algo'
