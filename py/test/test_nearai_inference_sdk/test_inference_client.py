"""Use the public Chat client against an in-memory, cryptographically signed Gateway."""

from __future__ import annotations

import asyncio
import gc
import hashlib
import json
import weakref
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
    AttestationVerificationResult,
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
    build_e2ee_request_aad,
    decrypt_e2ee_text,
    e2ee_field_aad,
    encrypt_e2ee_text,
)
from nearai_inference_sdk.utils.errors import api_failure
from nearai_inference_sdk.utils.fetch import FetchResponse

from .fixtures import APP_COMPOSE, TLS_FINGERPRINT, create_model_quote

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

    def __init__(
        self,
        signing_algo: str = 'ed25519',
        kind: str = 'provider_tee',
        *,
        seed: bytes = bytes([7]) * 32,
    ):
        self.signing_algo = signing_algo
        self.kind = kind
        self.gateway_requests = 0
        self.model_requests: list[str] = []
        self.completion_requests: list[httpx.Request] = []
        self.signature_requests = 0
        self.plaintexts: list[str] = []
        self.headers: list[httpx.Headers] = []
        self.attestation_headers: list[httpx.Headers] = []
        self.pins: list[str | None] = []
        self.peer_spki_fingerprint: str | None = TLS_FINGERPRINT
        self.quotes = {}
        self.signatures = {}
        self.metadata = {'providerType': 'vllm', 'attestationSupported': True}
        self.model_report_count = 1
        self.additional_model_is_invalid = False
        self.bad_quote = False
        self.tail_gate: asyncio.Event | None = None
        self.chat_body: bytes | None = None
        self.seed = seed
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
        if (
            request.url.path == '/v1/attestation/report'
            and 'model' not in request.url.params
        ):
            self.attestation_headers.append(request.headers)
            assert all(
                name not in request.headers
                for name in ('authorization', 'api-key', 'x-api-key')
            )
        else:
            self.headers.append(request.headers)
        if request.url.path.startswith('/v1/model/'):
            return httpx.Response(200, json={'metadata': self.metadata})
        if request.url.path == '/v1/attestation/report':
            await asyncio.sleep(
                0
            )  # Concurrent callers share the same pending preflight.
            nonce = request.url.params['nonce']
            if 'model' in request.url.params:
                self.model_requests.append(request.url.params['model'])
                attestations = [
                    self.attestation(nonce) for _ in range(self.model_report_count)
                ]
                if self.additional_model_is_invalid:
                    self.bad_quote = True
                    attestations.append(self.attestation(nonce))
                return httpx.Response(200, json={'model_attestations': attestations})
            self.gateway_requests += 1
            report = self.attestation(nonce)
            if request.url.params['include_tls_fingerprint'] == 'true':
                signer = bytes.fromhex(self.address.removeprefix('0x'))
                prefix = hashlib.sha256(
                    signer + bytes.fromhex(TLS_FINGERPRINT)
                ).digest()
                quote = replace(
                    self.quotes[report['intel_quote']],
                    report_data=prefix + bytes.fromhex(nonce),
                )
                self.quotes[report['intel_quote']] = quote
                report['report_data'] = quote.report_data.hex()
                report['tls_cert_fingerprint'] = TLS_FINGERPRINT
            return httpx.Response(200, json={'gateway_attestation': report})

        if request.url.path.startswith('/v1/signature/'):
            self.signature_requests += 1
            return httpx.Response(
                200,
                json=self.signatures[request.url.path.removeprefix('/v1/signature/')],
            )

        assert request.url.path == '/v1/chat/completions'
        self.completion_requests.append(request)
        body = json.loads(request.content)
        client_key = request.headers.get('x-client-pub-key')
        content = body['messages'][0]['content']
        if client_key:
            aad = e2ee_field_aad(
                build_e2ee_request_aad(
                    E2eeModelKey(signing_algo=self.signing_algo, public_key=client_key)
                ),
                'messages[].content',
            )
            content = decrypt_e2ee_text(content, self.encryption_key, 'content', aad)
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
        if self.chat_body is not None:
            completion_id, response_bytes = 'chat-1', self.chat_body

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
        chunks = (
            [response_bytes]
            if self.chat_body is not None
            else response_bytes.split(b'data: [DONE]')
        )
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
            return FetchResponse(
                status=response.status_code,
                body=response.content,
                peer_spki_fingerprint=self.peer_spki_fingerprint,
            )

        monkeypatch.setattr(cloud_api, 'default_fetch', fetch)

        def create_client(_client, fingerprint):
            self.pins.append(fingerprint)
            return httpx.AsyncClient(transport=httpx.MockTransport(self.handle))

        monkeypatch.setattr(InferenceClient, '_create_gateway_client', create_client)

    def client(self, api_key: str | None = 'test-key', **options) -> InferenceClient:
        options.setdefault('e2ee', True)
        options.setdefault('signing_algo', self.signing_algo)
        options.setdefault(
            'model_verification',
            ModelVerificationOptions(
                verifiers=ModelAttestationVerifiers(tdx_quote=self.quotes.__getitem__),
            ),
        )
        options.setdefault(
            'gateway_verification',
            GatewayVerificationOptions(
                include_spki_fingerprint=False,
                verifiers=AttestationVerifiers(tdx_quote=self.quotes.__getitem__),
            ),
        )
        return InferenceClient(
            api_key,
            base_url=BASE_URL,
            **options,
        )


@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
@pytest.mark.parametrize('kind', ['provider_tee', 'gateway'])
async def test_chat_decrypts_and_verifies_json_and_streaming_responses(
    monkeypatch, signing_algo, kind
):
    gateway = Gateway(signing_algo, kind)
    gateway.model_report_count = 2
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        preflight = await client.verify(MODEL)
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        assert completion.choices[0].message.content == 'Hello back'
        verified = await client.verify_response(completion.id)
        assert verified.id == completion.id
        assert verified.signature_kind == kind
        receipts = [verified]

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
        receipts.append(verified)
        for receipt in receipts:
            if kind == 'provider_tee':
                assert receipt.attestations == preflight.models
                assert receipt.attestation is preflight.models[0]
            else:
                assert receipt.attestation is preflight.gateway
                assert not hasattr(receipt, 'attestations')

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


@pytest.mark.parametrize('adapter_name', ['http_client', 'httpx2_client'])
async def test_one_openai_client_can_reuse_the_verified_transport(
    monkeypatch, gateway, adapter_name
):
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        openai = AsyncOpenAI(
            api_key='test-key',
            base_url=BASE_URL,
            http_client=getattr(client, adapter_name),
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


@pytest.mark.parametrize('tee', [False, True])
async def test_clear_response_cache_releases_records_and_preserves_session(
    monkeypatch, tee
):
    gateway = Gateway(kind='provider_tee' if tee else 'gateway')
    gateway.metadata = {
        'providerType': 'vllm' if tee else 'openai',
        'attestationSupported': tee,
    }
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=tee) as client:
        first = await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        await client.verify_response(first.id)
        record = weakref.ref(client._responses[first.id])
        expiry = client._responses[first.id].expiry
        assert expiry is not None and not expiry.cancelled()

        client.clear_response_cache()
        client.clear_response_cache()
        await asyncio.sleep(0)
        gc.collect()
        assert expiry.cancelled()
        assert record() is None
        with pytest.raises(ApiError) as error:
            await client.verify_response(first.id)
        assert error.value.failure.code == 'api.completion_not_found'

        next_response = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        await client.verify_response(next_response.id)
        assert gateway.gateway_requests == 1
        assert gateway.model_requests == ([MODEL] if tee else [])


async def test_clear_response_cache_ignores_a_late_response(monkeypatch):
    ready, resume = asyncio.Event(), asyncio.Event()

    class PausedGateway(Gateway):
        async def handle(self, request):
            response = await super().handle(request)
            if request.url.path == '/v1/chat/completions':
                ready.set()
                await resume.wait()
            return response

    gateway = PausedGateway()
    gateway.install(monkeypatch)
    async with gateway.client() as client:
        task = asyncio.create_task(
            client.chat.completions.create(model=MODEL, messages=MESSAGES)
        )
        try:
            await ready.wait()
            client.clear_response_cache()
        finally:
            resume.set()
        completion = await task
        with pytest.raises(ApiError) as error:
            await client.verify_response(completion.id)
        assert error.value.failure.code == 'api.completion_not_found'


async def test_clear_response_cache_during_stream_does_not_schedule_expiry(monkeypatch):
    gateway = Gateway()
    gateway.tail_gate = asyncio.Event()
    gateway.install(monkeypatch)
    async with gateway.client() as client:
        stream = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        try:
            first = await anext(stream)
            record = client._responses[first.id]
            client.clear_response_cache()
            gateway.tail_gate.set()
            chunks = [first, *[chunk async for chunk in stream]]
            await record.response_body
            await asyncio.sleep(0)
            assert chunks[0].choices[0].delta.content == 'Hello back'
            assert record.expiry is None
            with pytest.raises(ApiError) as error:
                await client.verify_response(first.id)
            assert error.value.failure.code == 'api.completion_not_found'
        finally:
            gateway.tail_gate.set()
            await stream.close()


@pytest.mark.parametrize('endpoint', ['chat/completions', 'responses'])
async def test_done_without_id_is_rejected_before_exposing_it(monkeypatch, endpoint):
    gateway = Gateway()
    original_handle = gateway.handle
    payload = (
        {'response': {'id': 'late-id'}}
        if endpoint == 'responses'
        else {'id': 'late-id'}
    )

    async def handle(request):
        if request.url.path == '/v1/' + endpoint:
            return httpx.Response(
                200,
                headers={'content-type': 'text/event-stream'},
                stream=ChunkStream(
                    [b'data: [DONE]\n\n', f'data: {json.dumps(payload)}\n\n'.encode()]
                ),
            )
        return await original_handle(request)

    monkeypatch.setattr(gateway, 'handle', handle)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        async with client.http_client.stream(
            'POST',
            BASE_URL + endpoint,
            json={
                'model': MODEL,
                'messages': MESSAGES,
                'input': 'Hello',
                'stream': True,
            },
        ) as response:
            with pytest.raises(ApiError, match='api.invalid_response'):
                await anext(response.aiter_bytes())
        with pytest.raises(ApiError, match='api.completion_not_found'):
            await client.verify_response('late-id')


@pytest.mark.parametrize('adapter_name', ['http_client', 'httpx2_client'])
async def test_external_openai_close_preserves_receipts_and_owner(
    monkeypatch, gateway, adapter_name
):
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        async with AsyncOpenAI(
            api_key='test-key',
            base_url=BASE_URL,
            http_client=getattr(client, adapter_name),
        ) as openai:
            completion = await openai.chat.completions.create(
                model=MODEL, messages=MESSAGES
            )
        verified = await client.verify_response(completion.id)
        assert verified.id == completion.id

        # Both the built-in Chat client and a new external adapter still work.
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        await client.verify_response(completion.id)
        async with AsyncOpenAI(
            api_key='test-key',
            base_url=BASE_URL,
            http_client=getattr(client, adapter_name),
        ) as openai:
            completion = await openai.chat.completions.create(
                model=MODEL, messages=MESSAGES
            )
        await client.verify_response(completion.id)

    assert gateway.gateway_requests == 1
    assert len(gateway.completion_requests) == 3


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
    monkeypatch.setattr(inference_client, 'time', lambda: 1_700_000_000 + now)

    async with gateway.client(attestation_cache_time_to_live_ms=1000) as client:
        await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        original = await client.verify(MODEL)
        now = 2
        await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        refreshed = await client.verify(MODEL)

    assert refreshed is not original
    assert original.verified_at == 1_700_000_000_000
    assert refreshed.verified_at == 1_700_000_002_000
    assert gateway.model_requests == [MODEL, MODEL]


@pytest.mark.parametrize('ttl_ms', [0, 60_000])
async def test_verify_checks_deployments_without_chat_and_obeys_cache_ttl(
    monkeypatch, gateway, ttl_ms
):
    gateway.install(monkeypatch)
    now = 1_700_000_000
    monkeypatch.setattr(inference_client, 'time', lambda: now)
    async with gateway.client(attestation_cache_time_to_live_ms=ttl_ms) as client:
        first = await client.verify(MODEL)
        assert isinstance(first, AttestationVerificationResult)
        assert first.gateway.tcb_status == 'UpToDate'
        assert len(first.models) == 1
        assert first.models[0].signer.signing_address == gateway.address
        now += 1
        second = await client.verify(MODEL)
        if ttl_ms == 0:
            assert second is not first
            assert second.verified_at == first.verified_at + 1000
        else:
            assert second is first
            assert second.verified_at == 1_700_000_000_000
        assert gateway.completion_requests == []
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        receipt = await client.verify_response(completion.id)
        if ttl_ms != 0:
            assert receipt.attestation is first.models[0]
    assert gateway.gateway_requests == (3 if ttl_ms == 0 else 1)
    assert len(gateway.model_requests) == gateway.gateway_requests


@pytest.mark.parametrize('attestation_supported', [True, False])
async def test_verify_returns_all_model_reports_or_gateway_only_results(
    monkeypatch, attestation_supported
):
    gateway = Gateway()
    gateway.model_report_count = 2
    gateway.metadata['attestationSupported'] = attestation_supported
    gateway.install(monkeypatch)

    async with gateway.client(e2ee=False) as client:
        first, second = await asyncio.gather(client.verify(MODEL), client.verify(MODEL))

    assert second is first
    assert first.gateway.signer.signing_address == gateway.address
    assert len(first.models) == (2 if attestation_supported else 0)
    assert all(item.tcb_status == 'UpToDate' for item in first.models)
    assert gateway.gateway_requests == 1
    assert gateway.model_requests == ([MODEL] if attestation_supported else [])
    assert gateway.completion_requests == []


@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
@pytest.mark.parametrize('e2ee', [False, True])
@pytest.mark.parametrize('stream', [False, True])
async def test_response_preserves_shared_signer_reports_from_its_preflight(
    monkeypatch, signing_algo, e2ee, stream
):
    gateway = Gateway(signing_algo)
    gateway.model_report_count = 2
    original_attestation = gateway.attestation

    def distinct_deployment(nonce):
        report = original_attestation(nonce)
        quote_id = report['intel_quote']
        compose = json.dumps({**json.loads(APP_COMPOSE), 'name': quote_id})
        report['info']['tcb_info']['app_compose'] = compose
        gateway.quotes[quote_id] = replace(
            gateway.quotes[quote_id],
            mr_config_id=b'\x01'
            + hashlib.sha256(compose.encode()).digest()
            + bytes(15),
        )
        return report

    monkeypatch.setattr(gateway, 'attestation', distinct_deployment)
    gateway.install(monkeypatch)
    now = 0
    monkeypatch.setattr(inference_client, 'monotonic', lambda: now)

    async with gateway.client(
        e2ee=e2ee, attestation_cache_time_to_live_ms=1000
    ) as client:
        original = await client.verify(MODEL)
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=stream
        )
        if stream:
            chunks = [chunk async for chunk in completion]
            completion_id = chunks[0].id
        else:
            completion_id = completion.id
        assert await client.verify(MODEL) is original
        assert len({item.deployment.app_compose for item in original.models}) == 2

        now = 2
        gateway.model_report_count = 3
        refreshed = await client.verify(MODEL)
        assert len(refreshed.models) == 3
        receipt = await client.verify_response(completion_id)

    assert receipt.attestations == original.models
    assert all(
        actual is expected
        for actual, expected in zip(receipt.attestations, original.models, strict=True)
    )
    assert receipt.attestation is original.models[0]
    assert gateway.model_requests == [MODEL, MODEL]


@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
@pytest.mark.parametrize('e2ee', [False, True])
@pytest.mark.parametrize('alternate_signer', [False, True])
async def test_response_stays_bound_to_selected_key_in_a_mixed_signer_group(
    monkeypatch, signing_algo, e2ee, alternate_signer
):
    gateway = Gateway(signing_algo)
    other = Gateway(signing_algo, seed=bytes([8]) * 32)
    other.quotes = gateway.quotes
    original_handle = gateway.handle

    async def handle(request):
        response = await original_handle(request)
        if (
            request.url.path == '/v1/attestation/report'
            and 'model' in request.url.params
        ):
            reports = response.json()['model_attestations']
            nonce = request.url.params['nonce']
            reports.extend([other.attestation(nonce), gateway.attestation(nonce)])
            return httpx.Response(200, json={'model_attestations': reports})
        if alternate_signer and request.url.path.startswith('/v1/signature/'):
            signature = response.json()
            text = signature['text']
            signature['signature'] = (
                other.key.sign(text.encode()).signature.hex()
                if signing_algo == 'ed25519'
                else other.key.sign_message(encode_defunct(text=text)).signature.hex()
            )
            signature['signing_address'] = other.address
            return httpx.Response(200, json=signature)
        return response

    monkeypatch.setattr(gateway, 'handle', handle)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=e2ee) as client:
        preflight = await client.verify(MODEL)
        assert [report.signer.signing_address for report in preflight.models] == [
            gateway.address,
            other.address,
            gateway.address,
        ]
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        assert (
            gateway.completion_requests[0].headers['x-model-pub-key']
            == gateway.public_key
        )
        if alternate_signer:
            with pytest.raises(VerificationError) as rejected:
                await client.verify_response(completion.id)
            assert rejected.value.failure.code == 'signature.signer_mismatch'
        else:
            receipt = await client.verify_response(completion.id)
            assert receipt.attestations == (preflight.models[0], preflight.models[2])
            assert receipt.attestation is preflight.models[0]


@pytest.mark.parametrize('e2ee', [False, True])
async def test_empty_model_reports_never_fall_back_to_gateway_only(monkeypatch, e2ee):
    gateway = Gateway()
    gateway.model_report_count = 0
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=e2ee) as client:
        with pytest.raises(VerificationError) as rejected:
            await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
    assert rejected.value.failure.code == 'policy.model_attestation_required'
    assert gateway.completion_requests == []


async def test_second_shared_signer_report_must_pass_deployment_policy(monkeypatch):
    gateway = Gateway()
    gateway.model_report_count = 2
    gateway.install(monkeypatch)
    checked = []

    def deployment_policy(model, deployment):
        checked.append((model, deployment))
        if len(checked) == 2:
            raise ValueError('second deployment rejected')

    async with gateway.client(deployment_policy=deployment_policy) as client:
        with pytest.raises(VerificationError) as rejected:
            await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )

    assert rejected.value.failure.code == 'provenance.verification_failed'
    assert len(checked) == 2
    assert gateway.completion_requests == []


async def test_failed_preverification_is_not_cached(monkeypatch):
    gateway = Gateway()
    gateway.bad_quote = True
    gateway.install(monkeypatch)
    async with gateway.client() as client:
        with pytest.raises(VerificationError) as raised:
            await client.verify(MODEL)
        assert raised.value.failure.code == 'policy.debug_enabled'
        gateway.bad_quote = False
        await client.verify(MODEL)
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        await client.verify_response(completion.id)
    assert gateway.gateway_requests == 2
    assert len(gateway.completion_requests) == 1


async def test_verify_rejects_an_empty_model_without_fetching_evidence(monkeypatch):
    gateway = Gateway()
    gateway.install(monkeypatch)
    async with gateway.client() as client:
        with pytest.raises(ApiError) as raised:
            await client.verify('')
        assert raised.value.failure.code == 'api.invalid_input'
        assert raised.value.failure.details['field'] == 'model'
    assert gateway.gateway_requests == 0


async def test_model_requests_wait_for_gateway_verification(monkeypatch):
    gateway = Gateway()
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
        preflight = asyncio.create_task(client.verify(MODEL))
        async with asyncio.timeout(1):
            await gateway_started.wait()
        chat = asyncio.create_task(
            client.chat.completions.create(model=MODEL, messages=MESSAGES)
        )
        await asyncio.sleep(0)
        assert not preflight.done()
        assert not chat.done()
        assert gateway.completion_requests == []
        assert gateway.pins == []
        assert gateway.headers == []
        assert gateway.model_requests == []

        release_gateway.set()
        await preflight
        assert model_verified.is_set()
        completion = await chat
        await client.verify_response(completion.id)

    assert gateway.gateway_requests == 1
    assert gateway.model_requests == [MODEL]
    assert len(gateway.completion_requests) == 1


@pytest.mark.parametrize('peer_fingerprint', [None, '44' * 32])
async def test_unverified_tls_peer_never_allows_chat(monkeypatch, peer_fingerprint):
    gateway = Gateway()
    gateway.peer_spki_fingerprint = peer_fingerprint
    gateway.install(monkeypatch)
    async with gateway.client(
        gateway_verification=GatewayVerificationOptions(
            verifiers=AttestationVerifiers(tdx_quote=gateway.quotes.__getitem__)
        )
    ) as client:
        with pytest.raises(VerificationError) as raised:
            await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
        assert raised.value.failure.code == (
            'binding.spki_fingerprint_required'
            if peer_fingerprint is None
            else 'binding.spki_fingerprint_mismatch'
        )
    # A rejected peer is never used for authenticated evidence requests.
    assert gateway.pins == []
    assert gateway.headers == []
    assert gateway.completion_requests == []


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


@pytest.mark.parametrize('streaming', [False, True])
@pytest.mark.parametrize('invalid_signature', [False, True])
async def test_terminal_verification_releases_bodies_but_preserves_cached_result(
    monkeypatch, streaming, invalid_signature
):
    gateway = Gateway()
    gateway.install(monkeypatch)

    # Unlike bytes, bytearray subclasses can be weakly referenced. They preserve
    # the exact captured bytes and still exercise the real signature verifier.
    class TrackedBytes(bytearray):
        pass

    async with gateway.client() as client:
        result = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=streaming
        )
        if streaming:
            chunks = [chunk async for chunk in result]
            completion_id = chunks[0].id
        else:
            completion_id = result.id
        record = client._responses[completion_id]
        await record.response_body
        await asyncio.sleep(0)
        expiry, expires_at = record.expiry, record.expires_at
        record.request_body = TrackedBytes(record.request_body)
        response_body = asyncio.get_running_loop().create_future()
        response_body.set_result(TrackedBytes(await record.response_body))
        record.response_body = response_body
        references = (
            weakref.ref(record.request_body),
            weakref.ref(response_body.result()),
            weakref.ref(response_body),
        )
        del response_body
        if invalid_signature:
            gateway.signatures[completion_id]['signature'] = '00' * 64

        async def verify():
            try:
                return await client.verify_response(completion_id)
            except VerificationError as error:
                assert invalid_signature
                assert error.failure.code == 'signature.invalid'
                return error

        first, concurrent = await asyncio.gather(verify(), verify())
        assert concurrent is first
        assert await verify() is first
        await asyncio.sleep(0)
        gc.collect()
        assert all(reference() is None for reference in references)
        assert client._responses[completion_id] is record
        assert record.expiry is expiry and record.expires_at == expires_at
        assert expiry is not None and not expiry.cancelled()
        assert gateway.signature_requests == 1


@pytest.mark.parametrize('unavailable', [False, True])
async def test_retryable_verification_retains_capture_until_success(
    monkeypatch, unavailable
):
    gateway = Gateway()
    gateway.install(monkeypatch)
    async with gateway.client() as client:
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        record = client._responses[completion.id]
        captured = record.request_body, record.response_body, record.session
        fetch_signature = record.session.attestation_client.fetch_completion_signature

        async def fail_once(*args, **kwargs):
            monkeypatch.setattr(
                record.session.attestation_client,
                'fetch_completion_signature',
                fetch_signature,
            )
            raise api_failure(
                'api.completion_signature_unavailable'
                if unavailable
                else 'api.http_status',
                retryable=not unavailable,
            )

        monkeypatch.setattr(
            record.session.attestation_client, 'fetch_completion_signature', fail_once
        )
        with pytest.raises(ApiError):
            await client.verify_response(completion.id)
        assert record.verification is None
        assert (record.request_body, record.response_body, record.session) == captured
        verified = await client.verify_response(completion.id)
        assert verified.id == completion.id
        assert record.request_body == b''
        assert record.response_body is None and record.session is None
    assert len(gateway.completion_requests) == 1


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
    sibling_started = asyncio.Event()
    sibling_cleaned_up = asyncio.Event()

    async def verify_quote(quote):
        result = gateway.quotes[quote]
        if result.debug_enabled:
            await sibling_started.wait()
            return result
        sibling_started.set()
        try:
            await asyncio.Future()
        finally:
            await asyncio.sleep(0)
            sibling_cleaned_up.set()

    async with gateway.client(
        model_verification=ModelVerificationOptions(
            verifiers=ModelAttestationVerifiers(tdx_quote=verify_quote)
        )
    ) as client:
        request = httpx.Request(
            'POST',
            BASE_URL + 'chat/completions',
            json={'model': MODEL, 'messages': MESSAGES},
        )
        async with asyncio.timeout(1):
            with pytest.raises(VerificationError) as raised:
                await client.send(request)
        assert raised.value.failure.code == 'policy.debug_enabled'
        assert sibling_cleaned_up.is_set()

    assert gateway.completion_requests == []


@pytest.mark.parametrize('reject_gateway', [False, True])
async def test_gateway_verification_precedes_authenticated_requests(
    monkeypatch, gateway, reject_gateway
):
    gateway.install(monkeypatch)

    async def verify_quote(quote):
        await asyncio.sleep(0)
        assert gateway.headers == []
        assert gateway.model_requests == []
        return replace(gateway.quotes[quote], debug_enabled=reject_gateway)

    async with gateway.client(
        gateway_verification=GatewayVerificationOptions(
            include_spki_fingerprint=False,
            verifiers=AttestationVerifiers(tdx_quote=verify_quote),
        )
    ) as client:
        if reject_gateway:
            with pytest.raises(VerificationError) as raised:
                await client.verify(MODEL)
            assert raised.value.failure.code == 'policy.debug_enabled'
            assert gateway.headers == []
        else:
            await client.verify(MODEL)
            assert gateway.model_requests == [MODEL]
            assert all(h['authorization'] == 'Bearer test-key' for h in gateway.headers)


async def test_configured_authentication_is_omitted_only_from_gateway_attestation(
    monkeypatch,
    gateway,
):
    gateway.install(monkeypatch)

    async with gateway.client(
        headers={'x-aggregator': 'app', 'Api-Key': 'stale-key'}
    ) as client:
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
    assert len(gateway.attestation_headers) == 1
    assert all(
        headers['x-aggregator'] == 'app' for headers in gateway.attestation_headers
    )
    assert all('api-key' not in headers for headers in gateway.headers)
    assert gateway.completion_requests[0].headers['x-tenant'] == 'alice'


@pytest.mark.parametrize('adapter_name', ['http_client', 'httpx2_client'])
async def test_external_openai_uses_configured_header_only_authentication(
    monkeypatch, gateway, adapter_name
):
    gateway.install(monkeypatch)

    async with gateway.client(
        api_key=None, headers={'X-API-Key': 'aggregator-key'}
    ) as client:
        openai_client = AsyncOpenAI(
            api_key='placeholder',
            base_url=BASE_URL,
            http_client=getattr(client, adapter_name),
        )
        completion = await openai_client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        await client.verify_response(completion.id)

    assert all(headers['x-api-key'] == 'aggregator-key' for headers in gateway.headers)
    assert all('authorization' not in headers for headers in gateway.headers)
    assert len(gateway.attestation_headers) == 1


@pytest.mark.parametrize('e2ee', [False, True])
async def test_async_request_body_is_sent_with_buffered_framing(
    monkeypatch, gateway, e2ee
):
    gateway.install(monkeypatch)
    body = json.dumps({'model': MODEL, 'messages': MESSAGES}).encode()

    async with gateway.client(e2ee=e2ee) as client:
        request = httpx.Request(
            'POST',
            BASE_URL + 'chat/completions',
            content=ChunkStream([body[:10], body[10:]]),
            headers={'Content-Type': 'application/json', 'Trailer': 'Digest'},
        )
        response = await client.http_client.send(request)
        await client.verify_response(response.json()['id'])

    sent = gateway.completion_requests[0]
    assert 'transfer-encoding' not in sent.headers
    assert 'trailer' not in sent.headers
    assert sent.headers['content-length'] == str(len(sent.content))
    assert gateway.plaintexts == ['Hello']


@pytest.mark.parametrize(
    'ending, valid',
    [
        pytest.param(b'data: {"id":"chat-1","choices":[]}\n\n', True, id='normal-EOF'),
        pytest.param(
            b'data: [DONE]\n\ndata: not-json\n\n', True, id='DONE-with-trailing-bytes'
        ),
        pytest.param(
            b'data: {"id":"other","choices":[]}\n\n',
            False,
            id='conflicting-response-ID',
        ),
        pytest.param(
            b'event: error\ndata: {"type":"error","error":{"message":"failed"}}\n\n',
            False,
            id='stream-error',
        ),
    ],
)
async def test_chat_stream_receipt(monkeypatch, gateway, ending, valid):
    gateway.chat_body = b'data: {"id":"chat-1","choices":[]}\n\n' + ending
    gateway.install(monkeypatch)
    for e2ee in (False, True):
        async with gateway.client(e2ee=e2ee) as client:
            response = await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES, 'stream': True},
                )
            )
            if valid:
                await response.aread()
                assert (await client.verify_response('chat-1')).id == 'chat-1'
            else:
                with pytest.raises(ApiError):
                    await response.aread()
                with pytest.raises(ApiError):
                    await client.verify_response('chat-1')
    assert gateway.signature_requests == (2 if valid else 0)


@pytest.mark.parametrize('stream', [False, True], ids=['json', 'stream'])
async def test_rejects_receipt_when_signed_chat_fails_decryption(
    monkeypatch, gateway, stream
):
    gateway.chat_body = (
        b'data: {"id":"chat-1","choices":[]}\n\n'
        b'data: {"id":"chat-1","choices":[{"delta":{"content":"invalid"}}]}\n\n'
        b'data: [DONE]\n\n'
        if stream
        else b'{"id":"chat-1","choices":[{"message":{"content":"invalid"}}]}'
    )
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=True) as client:
        with pytest.raises(VerificationError, match='e2ee.decryption_failed'):
            response = await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES, 'stream': stream},
                )
            )
            await response.aread()
        with pytest.raises((ApiError, VerificationError)):
            await client.verify_response('chat-1')
    assert gateway.signature_requests == 0


@pytest.mark.parametrize('adapter_name', ['http_client', 'httpx2_client'])
async def test_early_stream_close_is_not_a_verifiable_receipt(
    monkeypatch, gateway, adapter_name
):
    gateway.install(monkeypatch)

    async with (
        gateway.client() as client,
        AsyncOpenAI(
            api_key='test-key',
            base_url=BASE_URL,
            http_client=getattr(client, adapter_name),
        ) as openai,
    ):
        stream = await openai.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        chunk = await anext(stream)
        await stream.close()
        with pytest.raises(ApiError):
            await client.verify_response(chunk.id)

    assert gateway.signature_requests == 0


@pytest.mark.parametrize('adapter_name', ['http_client', 'httpx2_client'])
async def test_done_finishes_chat_while_receipt_waits_for_trailing_wire_bytes(
    monkeypatch, gateway, adapter_name
):
    gateway.tail_gate = asyncio.Event()
    gateway.install(monkeypatch)

    async with (
        gateway.client() as client,
        AsyncOpenAI(
            api_key='test-key',
            base_url=BASE_URL,
            http_client=getattr(client, adapter_name),
        ) as openai,
    ):
        stream = await openai.chat.completions.create(
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


@pytest.mark.parametrize('endpoint', ['chat/completions', 'responses', 'messages'])
async def test_native_inference_does_not_replay_server_errors(monkeypatch, endpoint):
    class FailingGateway(Gateway):
        async def handle(self, request):
            if request.url.path == '/v1/' + endpoint:
                self.completion_requests.append(request)
                return httpx.Response(
                    500, json={'error': {'message': 'fixture failure'}}
                )
            return await super().handle(request)

    gateway = FailingGateway()
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        with pytest.raises(Exception) as caught:
            if endpoint == 'messages':
                await client.messages.create(
                    model=MODEL, messages=MESSAGES, max_tokens=128
                )
            elif endpoint == 'responses':
                await client.responses.create(model=MODEL, input='Hello')
            else:
                await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        assert caught.value.status_code == 500
        assert len(gateway.completion_requests) == 1
