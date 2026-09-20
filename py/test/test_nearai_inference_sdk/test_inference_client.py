"""Use the public Chat client against an in-memory, cryptographically signed Gateway."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from eth_account import Account
from eth_account.messages import encode_defunct
from nacl.signing import SigningKey
from openai import AsyncOpenAI

from nearai_inference_sdk import (
    ApiError,
    AttestationVerifiers,
    E2eeModelKey,
    GatewayVerificationOptions,
    InferenceClient,
    ModelAttestationVerifiers,
    ModelVerificationOptions,
    VerificationError,
)
from nearai_inference_sdk.core import cloud_api, inference_client
from nearai_inference_sdk.core.e2ee import (
    EcdsaE2eeClientKeyPair,
    Ed25519E2eeClientKeyPair,
    decrypt_e2ee_text,
    encrypt_e2ee_text,
)
from nearai_inference_sdk.utils.fetch import FetchResponse

from .fixtures import APP_COMPOSE, create_model_quote


BASE_URL = 'https://gateway.test/v1/'
MODEL = 'test-model'
MESSAGES = [{'role': 'user', 'content': 'Hello'}]


class ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], tail_gate: asyncio.Event | None = None):
        self.chunks = chunks
        self.tail_gate = tail_gate

    async def __aiter__(self):
        for index, chunk in enumerate(self.chunks):
            if self.tail_gate is not None and index == len(self.chunks) - 1:
                await self.tail_gate.wait()
            yield chunk


class Gateway:
    """Real message crypto; only the hardware quote verifier is substituted."""

    def __init__(self, signing_algo: str = 'ed25519', kind: str = 'provider_tee'):
        self.signing_algo = signing_algo
        self.kind = kind
        self.gateway_requests = 0
        self.model_requests: list[str] = []
        self.completion_requests: list[httpx.Request] = []
        self.signature_requests = 0
        self.plaintexts: list[str] = []
        self.headers: list[httpx.Headers] = []
        self.quotes = {}
        self.signatures = {}
        self.additional_model_is_invalid = False
        self.bad_quote = False
        self.tail_gate: asyncio.Event | None = None
        self.seed = bytes([7]) * 32
        if signing_algo == 'ed25519':
            self.key = SigningKey(self.seed)
            self.public_key = bytes(self.key.verify_key).hex()
            self.address = self.public_key
            self.encryption_key = Ed25519E2eeClientKeyPair(
                public_key=self.public_key,
                x25519_secret_key=bytes(self.key.to_curve25519_private_key()),
            )
        else:
            private_key = ec.derive_private_key(
                int.from_bytes(self.seed), ec.SECP256K1()
            )
            self.key = Account.from_key(self.seed)
            self.public_key = (
                private_key.public_key()
                .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]
                .hex()
            )
            self.address = self.key.address
            self.encryption_key = EcdsaE2eeClientKeyPair(
                public_key=self.public_key, private_key=private_key
            )

    def attestation(self, nonce: str):
        quote_id = f'{len(self.quotes) + 1:02x}'
        quote = create_model_quote(signing_address=self.address)
        quote = replace(
            quote,
            report_data=quote.report_data[:32] + bytes.fromhex(nonce),
            debug_enabled=self.bad_quote,
        )
        self.quotes[quote_id] = quote
        return {
            'request_nonce': nonce,
            'signing_algo': self.signing_algo,
            'signing_address': self.address,
            'signing_public_key': self.public_key,
            'intel_quote': quote_id,
            'report_data': quote.report_data.hex(),
            'event_log': [
                {
                    'digest': '00' * 48,
                    'imr': 3,
                    'event_type': 0,
                    'event': 'compose-hash',
                    'event_payload': 'beef',
                }
            ],
            'info': {'tcb_info': {'app_compose': APP_COMPOSE}},
        }

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.headers.append(request.headers)
        if request.url.path == '/v1/attestation/report':
            await asyncio.sleep(
                0
            )  # Concurrent callers share the same pending preflight.
            nonce = request.url.params['nonce']
            if 'model' in request.url.params:
                self.model_requests.append(request.url.params['model'])
                attestations = [self.attestation(nonce)]
                if self.additional_model_is_invalid:
                    self.bad_quote = True
                    attestations.append(self.attestation(nonce))
                return httpx.Response(200, json={'model_attestations': attestations})
            self.gateway_requests += 1
            assert request.url.params['include_tls_fingerprint'] == 'false'
            return httpx.Response(
                200, json={'gateway_attestation': self.attestation(nonce)}
            )

        if request.url.path.startswith('/v1/signature/'):
            self.signature_requests += 1
            return httpx.Response(
                200, json=self.signatures[request.url.path.rsplit('/', 1)[1]]
            )

        assert request.url.path == '/v1/chat/completions'
        self.completion_requests.append(request)
        body = json.loads(request.content)
        client_key = request.headers.get('x-client-pub-key')
        content = body['messages'][0]['content']
        if client_key:
            content = decrypt_e2ee_text(content, self.encryption_key, 'content')
        self.plaintexts.append(content)
        response_content = 'Hello back'
        if client_key:
            response_content = encrypt_e2ee_text(
                response_content,
                E2eeModelKey(signing_algo=self.signing_algo, public_key=client_key),
            )
        completion_id = f'chatcmpl-{len(self.completion_requests)}'
        completion = {
            'id': completion_id,
            'created': 0,
            'model': body['model'],
            'object': 'chat.completion',
            'choices': [
                {
                    'index': 0,
                    'message': {'role': 'assistant', 'content': response_content},
                    'finish_reason': 'stop',
                }
            ],
        }
        if body.get('stream'):
            completion['object'] = 'chat.completion.chunk'
            completion['choices'] = [
                {
                    'index': 0,
                    'delta': {'content': response_content},
                    'finish_reason': 'stop',
                }
            ]
            # A multiline CRLF event exercises both decryption and receipt capture.
            text = json.dumps(completion)
            first, rest = text.split(',', 1)
            response_bytes = f'data: {first},\r\ndata: {rest}\r\n\r\n'.encode()
            response_bytes += b'data: [DONE]\r\n\r\n'
            if self.tail_gate is not None:
                response_bytes += b': signed trailing bytes\r\n\r\n'
            content_type = 'text/event-stream'
        else:
            response_bytes = json.dumps(completion).encode()
            content_type = 'application/json'

        signed_text = ':'.join(
            (
                hashlib.sha256(request.content).hexdigest(),
                hashlib.sha256(response_bytes).hexdigest(),
            )
        )
        if self.kind == 'provider_tee':
            signed_text = f'{body["model"]}:{signed_text}'
        signature = (
            self.key.sign(signed_text.encode()).signature.hex()
            if self.signing_algo == 'ed25519'
            else self.key.sign_message(encode_defunct(text=signed_text)).signature.hex()
        )
        self.signatures[completion_id] = {
            'text': signed_text,
            'signature': signature,
            'signing_algo': self.signing_algo,
            'signing_address': self.address,
            'signature_kind': self.kind,
        }
        chunks = response_bytes.split(b'data: [DONE]')
        if len(chunks) == 2:
            chunks[1] = b'data: [DONE]' + chunks[1]
        if self.tail_gate is not None:
            done, tail = chunks[-1].split(b': signed trailing bytes')
            chunks[-1] = done
            chunks.append(b': signed trailing bytes' + tail)
        return httpx.Response(
            200,
            stream=ChunkStream(chunks, self.tail_gate),
            headers={'content-type': content_type},
        )

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fetch(url, *, headers=None, **kwargs):
            response = await self.handle(httpx.Request('GET', url, headers=headers))
            return FetchResponse(status=response.status_code, body=response.content)

        monkeypatch.setattr(cloud_api, 'default_fetch', fetch)
        monkeypatch.setattr(
            InferenceClient,
            '_create_gateway_client',
            lambda _client, _binding: httpx.AsyncClient(
                transport=httpx.MockTransport(self.handle)
            ),
        )

    def client(self, **options) -> InferenceClient:
        return InferenceClient(
            'test-key',
            base_url=BASE_URL,
            signing_algo=self.signing_algo,
            gateway_verification=GatewayVerificationOptions(
                include_spki_fingerprint=False,
                verifiers=AttestationVerifiers(quote=self.quotes.__getitem__),
            ),
            model_verification=ModelVerificationOptions(
                verifiers=ModelAttestationVerifiers(quote=self.quotes.__getitem__),
            ),
            **options,
        )


@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
@pytest.mark.parametrize('kind', ['provider_tee', 'gateway'])
async def test_chat_decrypts_and_verifies_json_and_streaming_responses(
    monkeypatch, signing_algo, kind
):
    gateway = Gateway(signing_algo, kind)
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        assert completion.choices[0].message.content == 'Hello back'
        verified = await client.verify_response(completion.id)
        assert verified.signature_kind == kind

        stream = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        chunks = [chunk async for chunk in stream]
        assert (
            ''.join(chunk.choices[0].delta.content or '' for chunk in chunks)
            == 'Hello back'
        )
        verified = await client.verify_response(chunks[0].id)
        assert verified.signature_kind == kind

    assert gateway.plaintexts == ['Hello', 'Hello']
    assert gateway.gateway_requests == 1
    assert gateway.model_requests == [MODEL]
    assert gateway.signature_requests == 2
    assert all(
        'Hello' not in request.content.decode()
        for request in gateway.completion_requests
    )


@pytest.fixture(params=['direct', 'ohttp'])
def gateway(request):
    if request.param == 'ohttp':
        from .test_inference_ohttp import ObliviousGateway

        return ObliviousGateway()
    return Gateway()


async def test_one_openai_client_can_reuse_the_verified_transport(monkeypatch, gateway):
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        openai = AsyncOpenAI(
            api_key='test-key', base_url=BASE_URL, http_client=client.http_client
        )
        first, second = await asyncio.gather(
            openai.chat.completions.create(model=MODEL, messages=MESSAGES),
            openai.chat.completions.create(model=MODEL, messages=MESSAGES),
        )
        await asyncio.gather(
            client.verify_response(first.id), client.verify_response(second.id)
        )

    assert gateway.gateway_requests == 1
    assert gateway.model_requests == [MODEL]
    assert len(gateway.completion_requests) == 2


async def test_cancelling_one_chat_preserves_shared_preflight(monkeypatch, gateway):
    preflight_started = asyncio.Event()
    release_preflight = asyncio.Event()
    handle = gateway.handle

    async def hold_preflight(request):
        if (
            request.url.path == '/v1/attestation/report'
            and 'model' not in request.url.params
        ):
            preflight_started.set()
            await release_preflight.wait()
        return await handle(request)

    monkeypatch.setattr(gateway, 'handle', hold_preflight)
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        cancelled = asyncio.create_task(
            client.chat.completions.create(model=MODEL, messages=MESSAGES)
        )
        await preflight_started.wait()
        continuing = asyncio.create_task(
            client.chat.completions.create(model=MODEL, messages=MESSAGES)
        )
        await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        release_preflight.set()
        completion = await continuing
        await client.verify_response(completion.id)

    assert gateway.gateway_requests == 1
    assert gateway.model_requests == [MODEL]
    assert len(gateway.completion_requests) == 1
    assert gateway.signature_requests == 1


async def test_attestation_cache_is_scoped_to_the_requested_model(monkeypatch, gateway):
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        for model in [MODEL, 'another-model', MODEL]:
            await client.chat.completions.create(model=model, messages=MESSAGES)

    assert gateway.model_requests == [MODEL, 'another-model']


async def test_expired_attestations_are_refreshed_before_sending_chat(
    monkeypatch, gateway
):
    gateway.install(monkeypatch)
    now = 0
    monkeypatch.setattr(inference_client, 'monotonic', lambda: now)

    async with gateway.client(attestation_cache_time_to_live_ms=1000) as client:
        await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        now = 2
        await client.chat.completions.create(model=MODEL, messages=MESSAGES)

    assert gateway.model_requests == [MODEL, MODEL]


async def test_concurrent_receipt_checks_share_signature_retrieval(
    monkeypatch, gateway
):
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        first, second = await asyncio.gather(
            client.verify_response(completion.id), client.verify_response(completion.id)
        )

    assert first == second
    assert gateway.signature_requests == 1


async def test_disabling_encryption_keeps_preflight_and_response_verification(
    monkeypatch,
):
    gateway = Gateway()
    gateway.install(monkeypatch)

    async with gateway.client(
        e2ee=False, attestation_cache_time_to_live_ms=0
    ) as client:
        for _ in range(2):
            completion = await client.chat.completions.create(
                model=MODEL, messages=MESSAGES
            )
            await client.verify_response(completion.id)

    assert gateway.model_requests == [MODEL, MODEL]
    assert all(
        'x-client-pub-key' not in request.headers
        for request in gateway.completion_requests
    )
    assert gateway.plaintexts == ['Hello', 'Hello']


@pytest.mark.parametrize('failure', ['quote', 'deployment_policy'])
async def test_failed_preflight_never_sends_the_chat_request(monkeypatch, failure):
    gateway = Gateway()
    gateway.install(monkeypatch)
    gateway.bad_quote = failure == 'quote'

    def reject_deployment(model, deployment):
        raise ValueError('Deployment is not approved')

    options = (
        {'deployment_policy': reject_deployment}
        if failure == 'deployment_policy'
        else {}
    )
    async with gateway.client(**options) as client:
        request = httpx.Request(
            'POST',
            BASE_URL + 'chat/completions',
            json={'model': MODEL, 'messages': MESSAGES},
        )
        with pytest.raises(VerificationError) as raised:
            await client.send(request)

    assert raised.value.failure.code == (
        'policy.debug_enabled'
        if failure == 'quote'
        else 'provenance.verification_failed'
    )
    assert gateway.completion_requests == []


async def test_every_returned_model_report_must_pass_preflight(monkeypatch):
    gateway = Gateway()
    gateway.additional_model_is_invalid = True
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        request = httpx.Request(
            'POST',
            BASE_URL + 'chat/completions',
            json={'model': MODEL, 'messages': MESSAGES},
        )
        with pytest.raises(VerificationError):
            await client.send(request)

    assert gateway.completion_requests == []


async def test_configured_authentication_is_shared_with_evidence_and_chat(
    monkeypatch,
    gateway,
):
    gateway.install(monkeypatch)

    async with gateway.client(headers={'x-aggregator': 'app'}) as client:
        completion = await client.chat.completions.create(
            model=MODEL,
            messages=MESSAGES,
            extra_headers={'authorization': 'Bearer per-request', 'x-tenant': 'alice'},
        )
        await client.verify_response(completion.id)

    assert all(
        headers['authorization'] == 'Bearer test-key' for headers in gateway.headers
    )
    assert all(headers['x-aggregator'] == 'app' for headers in gateway.headers)
    assert gateway.completion_requests[0].headers['x-tenant'] == 'alice'


async def test_early_stream_close_is_not_a_verifiable_receipt(monkeypatch, gateway):
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        stream = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        chunk = await anext(stream)
        await stream.close()
        with pytest.raises(ApiError):
            await client.verify_response(chunk.id)

    assert gateway.signature_requests == 0


async def test_done_finishes_chat_while_receipt_waits_for_trailing_wire_bytes(
    monkeypatch,
    gateway,
):
    gateway.tail_gate = asyncio.Event()
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        stream = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        try:
            # OpenAI ends at [DONE]; receipt capture must continue independently.
            async with asyncio.timeout(1):
                chunks = [chunk async for chunk in stream]
            verification = asyncio.create_task(client.verify_response(chunks[0].id))
            await asyncio.sleep(0)
            assert not verification.done()
            gateway.tail_gate.set()
            verified = await verification
            assert verified.signature_kind == 'provider_tee'
        finally:
            gateway.tail_gate.set()
