"""Use the public Chat client against an in-memory, cryptographically signed Gateway."""

from __future__ import annotations

import asyncio
import hashlib
import json
import tracemalloc
from dataclasses import replace
from io import BytesIO

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from eth_account import Account
from eth_account.messages import encode_defunct
from nacl.signing import SigningKey
from openai import APIConnectionError, AsyncOpenAI, BadRequestError

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
    decrypt_e2ee_text,
    encrypt_e2ee_text,
)
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

    def __init__(self, signing_algo: str = 'ed25519', kind: str = 'provider_tee'):
        self.signing_algo = signing_algo
        self.kind = kind
        self.gateway_requests = 0
        self.model_requests: list[str] = []
        self.completion_requests: list[httpx.Request] = []
        self.signature_requests = 0
        self.plaintexts: list[str] = []
        self.headers: list[httpx.Headers] = []
        self.pins: list[str | None] = []
        self.peer_spki_fingerprint: str | None = TLS_FINGERPRINT
        self.quotes = {}
        self.signatures = {}
        self.metadata = {'providerType': 'vllm', 'attestationSupported': True}
        self.model_report_count = 1
        self.additional_model_is_invalid = False
        self.bad_quote = False
        self.response_content = 'Hello back'
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
            content = decrypt_e2ee_text(content, self.encryption_key, 'content')
        self.plaintexts.append(content)
        response_content = self.response_content
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
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        assert completion.choices[0].message.content == 'Hello back'
        verified = await client.verify_response(completion.id)
        assert verified.id == completion.id
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


async def test_external_openai_close_preserves_receipts_and_owner(monkeypatch, gateway):
    gateway.install(monkeypatch)

    async with gateway.client() as client:
        async with AsyncOpenAI(
            api_key='test-key', base_url=BASE_URL, http_client=client.http_client
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
            api_key='test-key', base_url=BASE_URL, http_client=client.http_client
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

    async with gateway.client(max_cache_entries=1) as client:
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
        with pytest.raises(ApiError, match='api.invalid_input'):
            await client.verify('different-model')
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


async def test_model_verification_overlaps_gateway_but_chat_waits_for_both(monkeypatch):
    gateway = Gateway()
    gateway.install(monkeypatch)
    release_gateway = asyncio.Event()
    model_verified = asyncio.Event()

    async def verify_gateway_quote(quote):
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
            await model_verified.wait()
        chat = asyncio.create_task(
            client.chat.completions.create(model=MODEL, messages=MESSAGES)
        )
        await asyncio.sleep(0)
        assert not preflight.done()
        assert not chat.done()
        assert gateway.completion_requests == []
        assert gateway.pins == [TLS_FINGERPRINT]

        release_gateway.set()
        await preflight
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
    # Pinning uses the observed peer, never the report's unauthenticated claim.
    assert gateway.pins == ([] if peer_fingerprint is None else [peer_fingerprint])
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


async def test_configured_authentication_is_shared_with_evidence_and_chat(
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
    assert all('api-key' not in headers for headers in gateway.headers)
    assert gateway.completion_requests[0].headers['x-tenant'] == 'alice'


async def test_external_openai_uses_configured_header_only_authentication(
    monkeypatch, gateway
):
    gateway.install(monkeypatch)

    async with gateway.client(
        api_key=None, headers={'X-API-Key': 'aggregator-key'}
    ) as client:
        openai_client = AsyncOpenAI(
            api_key='placeholder',
            base_url=BASE_URL,
            http_client=client.http_client,
        )
        completion = await openai_client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        await client.verify_response(completion.id)

    assert all(headers['x-api-key'] == 'aggregator-key' for headers in gateway.headers)
    assert all('authorization' not in headers for headers in gateway.headers)


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


@pytest.mark.parametrize('direct', [False, True])
async def test_stream_finishing_during_close_does_not_create_an_expiry_timer(
    monkeypatch, direct
):
    if direct:
        from .test_direct_inference_client import DirectEndpoint

        gateway = DirectEndpoint()
    else:
        gateway = Gateway()
    gateway.install(monkeypatch)
    client = gateway.client(e2ee=False)
    response = await client.http_client.send(
        httpx.Request(
            'POST',
            BASE_URL + 'chat/completions',
            json={'model': MODEL, 'messages': MESSAGES, 'stream': True},
        ),
        stream=True,
    )
    chunks = response.aiter_bytes()
    await anext(chunks)
    record = next(iter(client._responses.values()))
    assert not record.response_body.done()
    assert record.expiry is None

    closing = asyncio.Event()
    release = asyncio.Event()
    session_client = next(iter(client._http_clients.values()))
    original_close = session_client.aclose

    async def blocked_close():
        closing.set()
        await release.wait()
        await original_close()

    monkeypatch.setattr(session_client, 'aclose', blocked_close)
    close_task = asyncio.create_task(client.aclose())
    try:
        async with asyncio.timeout(2):
            await closing.wait()
        assert client._chat_client.is_closed
        # Finish a registered stream after teardown cancelled existing timers,
        # while it is still awaiting the session transport's close operation.
        async for _ in chunks:
            pass
        await asyncio.sleep(0)
        assert record.response_body.done()
    finally:
        release.set()
        await close_task
        await response.aclose()
    assert client._responses == {}
    assert record.expiry is None or record.expiry.cancelled()


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
            verification.cancel()
            with pytest.raises(asyncio.CancelledError):
                await verification
            gateway.tail_gate.set()
            verified = await client.verify_response(chunks[0].id)
            assert verified.signature_kind == 'provider_tee'
        finally:
            gateway.tail_gate.set()


@pytest.mark.parametrize('value', [0, -1, 1.5, float('inf'), True])
def test_rejects_invalid_cache_capacity_options(gateway, value):
    for field in ('max_body_bytes', 'max_cache_entries', 'max_receipt_cache_bytes'):
        with pytest.raises(ApiError):
            gateway.client(**{field: value})


async def test_cache_entry_limits_evict_sessions_and_receipts(monkeypatch, gateway):
    gateway.install(monkeypatch)
    async with gateway.client(max_cache_entries=1) as client:
        first = await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        second = await client.chat.completions.create(
            model='other-model', messages=MESSAGES
        )
        with pytest.raises(ApiError, match='api.completion_not_found'):
            await client.verify_response(first.id)
        await client.verify_response(second.id)
        await client.verify(MODEL)
        assert gateway.gateway_requests == 3


async def test_byte_budget_evicts_old_receipts_and_preserves_them_on_oversize(
    monkeypatch, gateway
):
    gateway.install(monkeypatch)
    request = httpx.Request(
        'POST',
        BASE_URL + 'chat/completions',
        json={'model': MODEL, 'messages': MESSAGES},
    )
    async with gateway.client(e2ee=False) as client:
        response = await client.send(request)
        wire = await response.aread()
        budget = len(request.content) + len(wire) + 10
    async with gateway.client(e2ee=False, max_receipt_cache_bytes=budget) as client:

        async def send():
            response = await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
            return json.loads(await response.aread())['id']

        first, second = await send(), await send()
        await asyncio.sleep(0)
        with pytest.raises(ApiError, match='api.completion_not_found'):
            await client.verify_response(first)
        before = len(gateway.completion_requests)
        with pytest.raises(ApiError, match='api.body_too_large'):
            await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={
                        'model': MODEL,
                        'messages': [{'role': 'user', 'content': 'x' * budget}],
                    },
                )
            )
        assert len(gateway.completion_requests) == before
        await client.verify_response(second)


@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
async def test_e2ee_receipt_budget_counts_wire_bytes_not_input_whitespace(
    monkeypatch, signing_algo
):
    gateway = Gateway(signing_algo)
    handle = gateway.handle
    receipt_sizes = []

    async def capture(request):
        response = await handle(request)
        if request.url.path == '/v1/chat/completions':
            receipt_sizes.append(len(request.content) + len(await response.aread()))
        return response

    gateway.handle = capture
    gateway.install(monkeypatch)
    payload = {'model': MODEL, 'messages': MESSAGES}
    async with gateway.client() as client:
        response = await client.send(
            httpx.Request('POST', BASE_URL + 'chat/completions', json=payload)
        )
        await response.aread()
    budget = receipt_sizes[-1]
    formatted = json.dumps(payload, indent=2048).encode()
    assert len(formatted) > budget

    async with gateway.client(
        max_body_bytes=len(formatted), max_receipt_cache_bytes=budget
    ) as client:
        response = await client.send(
            httpx.Request('POST', BASE_URL + 'chat/completions', content=formatted)
        )
        result = json.loads(await response.aread())
        assert result['choices'][0]['message']['content'] == 'Hello back'
        assert receipt_sizes[-1] == budget
        await client.verify_response(result['id'])

    before = len(gateway.completion_requests)
    async with gateway.client(max_body_bytes=len(formatted) - 1) as client:
        with pytest.raises(ApiError, match='api.body_too_large'):
            await client.send(
                httpx.Request('POST', BASE_URL + 'chat/completions', content=formatted)
            )
    assert len(gateway.completion_requests) == before


@pytest.mark.parametrize(
    'limits', [{'max_body_bytes': 10}, {'max_receipt_cache_bytes': 10}]
)
async def test_large_request_fails_before_preflight(monkeypatch, gateway, limits):
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False, **limits) as client:
        with pytest.raises(ApiError, match='api.body_too_large'):
            await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
    assert gateway.gateway_requests == 0
    assert not gateway.completion_requests


async def test_sync_request_stream_stops_at_body_limit(monkeypatch, gateway):
    gateway.install(monkeypatch)
    consumed = 0

    def chunks():
        nonlocal consumed
        for _ in range(10):
            consumed += 1
            yield b'x' * 512

    async with gateway.client(max_body_bytes=1024) as client:
        with pytest.raises(ApiError, match='api.body_too_large'):
            await client.send(
                httpx.Request('POST', BASE_URL + 'chat/completions', content=chunks())
            )
    assert consumed == 3
    assert gateway.gateway_requests == 0


@pytest.mark.parametrize('asynchronous', [False, True])
async def test_oversized_request_closes_content_generator(monkeypatch, asynchronous):
    gateway = Gateway()
    gateway.install(monkeypatch)
    closed = asyncio.Event()

    def chunks():
        try:
            yield b'x' * 11
            yield b'unread'
        finally:
            closed.set()

    async def async_chunks():
        try:
            yield b'x' * 11
            yield b'unread'
        finally:
            closed.set()

    request = httpx.Request(
        'POST',
        BASE_URL + 'chat/completions',
        content=async_chunks() if asynchronous else chunks(),
    )
    async with gateway.client(max_body_bytes=10) as client:
        with pytest.raises(ApiError, match='api.body_too_large'):
            await client.send(request)
        assert closed.is_set()
    assert gateway.gateway_requests == 0


async def test_oversized_request_keeps_caller_owned_file_open(monkeypatch):
    gateway = Gateway()
    gateway.install(monkeypatch)
    with BytesIO(b'x' * 11) as source:
        request = httpx.Request('POST', BASE_URL + 'chat/completions', content=source)
        async with gateway.client(max_body_bytes=10) as client:
            with pytest.raises(ApiError, match='api.body_too_large'):
                await client.send(request)
        assert not source.closed


@pytest.mark.parametrize('asynchronous', [False, True])
@pytest.mark.parametrize('outcome', ['oversized', 'read_error', 'success'])
@pytest.mark.parametrize('argument', ['stream', 'content'])
async def test_send_closes_original_request_stream(
    monkeypatch, gateway, asynchronous, outcome, argument
):
    gateway.install(monkeypatch)
    closed = 0
    body = json.dumps({'model': MODEL, 'messages': MESSAGES}).encode()

    def chunks():
        yield body[:10]
        if outcome == 'read_error':
            raise OSError('broken request stream')
        yield body[10:]

    class SyncStream(httpx.SyncByteStream):
        def __iter__(self):
            return chunks()

        def close(self):
            nonlocal closed
            closed += 1

    class AsyncStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for chunk in chunks():
                yield chunk

        async def aclose(self):
            nonlocal closed
            await asyncio.sleep(0)
            closed += 1

    stream = AsyncStream() if asynchronous else SyncStream()
    request = httpx.Request('POST', BASE_URL + 'chat/completions', **{argument: stream})
    async with gateway.client(
        e2ee=False, max_body_bytes=10 if outcome == 'oversized' else 4096
    ) as client:
        if outcome == 'success':
            response = await client.send(request)
            await response.aclose()
        else:
            error = ApiError if outcome == 'oversized' else OSError
            with pytest.raises(error):
                await client.send(request)
            assert gateway.gateway_requests == 0
    assert closed == 1


async def test_cancelled_request_read_closes_original_stream(monkeypatch, gateway):
    gateway.install(monkeypatch)
    started = asyncio.Event()
    closed = asyncio.Event()

    class StalledStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'{'
            started.set()
            await asyncio.Event().wait()

        async def aclose(self):
            await asyncio.sleep(0)
            closed.set()

    async with gateway.client() as client:
        task = asyncio.create_task(
            client.send(
                httpx.Request(
                    'POST', BASE_URL + 'chat/completions', stream=StalledStream()
                )
            )
        )
        await asyncio.wait_for(started.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert closed.is_set()
    assert gateway.gateway_requests == 0


async def test_sync_request_stream_with_disabled_receipt_retention(
    monkeypatch, gateway
):
    gateway.install(monkeypatch)
    body = json.dumps({'model': MODEL, 'messages': MESSAGES}).encode()
    async with gateway.client(
        e2ee=False, response_cache_time_to_live_ms=0, max_receipt_cache_bytes=1
    ) as client:
        response = await client.send(
            httpx.Request(
                'POST',
                BASE_URL + 'chat/completions',
                content=iter([body[:10], body[10:]]),
            )
        )
        assert json.loads(await response.aread())['id']
        assert not client._responses
    assert gateway.plaintexts == ['Hello']


@pytest.mark.parametrize('status', [200, 400])
@pytest.mark.parametrize('interface', ['send', 'openai'])
async def test_fragmented_response_has_bounded_consumer_memory(
    monkeypatch, status, interface
):
    gateway = Gateway()
    gateway.response_content = 'x' * 200_000
    original = gateway.handle
    closed = asyncio.Event()
    wire_body = b''

    class Fragments(httpx.AsyncByteStream):
        def __init__(self, body):
            self.body = body

        async def __aiter__(self):
            for offset in range(0, len(self.body), 2):
                yield self.body[offset : offset + 2]

        async def aclose(self):
            closed.set()

    async def respond(request):
        nonlocal wire_body
        response = await original(request)
        if request.url.path == '/v1/chat/completions':
            wire_body = await response.aread()
            return httpx.Response(
                status, headers=response.headers, stream=Fragments(wire_body)
            )
        return response

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False) as client:
        await client.verify(MODEL)
        async with AsyncOpenAI(
            api_key='test-key',
            base_url=BASE_URL,
            http_client=client.http_client,
            max_retries=0,
        ) as openai:
            tracemalloc.start()
            try:
                if interface == 'send':
                    response = await client.send(
                        httpx.Request(
                            'POST',
                            BASE_URL + 'chat/completions',
                            json={'model': MODEL, 'messages': MESSAGES},
                        )
                    )
                    assert await response.aread() == wire_body
                    completion_id = response.json()['id']
                elif status == 200:
                    completion = await openai.chat.completions.create(
                        model=MODEL, messages=MESSAGES
                    )
                    completion_id = completion.id
                    assert (
                        completion.choices[0].message.content
                        == gateway.response_content
                    )
                else:
                    with pytest.raises(BadRequestError) as failure:
                        await openai.chat.completions.create(
                            model=MODEL, messages=MESSAGES
                        )
                    assert failure.value.response.content == wire_body
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            assert peak < len(wire_body) * 8
            if status == 200:
                await client.verify_response(completion_id)
            else:
                with pytest.raises(ApiError, match='api.completion_not_found'):
                    await client.verify_response(json.loads(wire_body)['id'])
    assert closed.is_set()


@pytest.mark.parametrize(
    ('wire', 'has_id'),
    [
        (b':\n\n' * 65536, False),
        (b':\n\n' * 65536 + b'data: {"id": "chat-tail"}', True),
        (b'data: {"id": "chat-lines"}\n\n' + b':\n' * 100000 + b'\n', True),
        (b'data:   \n' * 20000 + b'data: {"id": "chat-data-lines"}\n\n', True),
    ],
    ids=['missing-id', 'unfinished-id-event', 'comment-lines-after-id', 'data-lines'],
)
@pytest.mark.parametrize('e2ee', [False, True])
async def test_sse_capture_has_bounded_memory(monkeypatch, wire, has_id, e2ee):
    gateway = Gateway()
    original = gateway.handle

    class Fragments(httpx.AsyncByteStream):
        async def __aiter__(self):
            for offset in range(0, len(wire), 2):
                yield wire[offset : offset + 2]

    async def respond(request):
        if request.url.path == '/v1/chat/completions':
            return httpx.Response(
                200,
                headers={'content-type': 'text/event-stream'},
                stream=Fragments(),
            )
        return await original(request)

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=e2ee) as client:
        response = await client.send(
            httpx.Request(
                'POST',
                BASE_URL + 'chat/completions',
                json={'model': MODEL, 'messages': MESSAGES, 'stream': True},
            )
        )
        tracemalloc.start()
        try:
            if has_id:
                assert await response.aread() == wire
            else:
                with pytest.raises(ApiError, match='api.invalid_response'):
                    await response.aread()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < len(wire) * 8


@pytest.mark.parametrize('cancel_all', [False, True])
async def test_receipt_cancellation_preserves_shared_waiters_and_releases_capacity(
    monkeypatch, gateway, cancel_all
):
    original = gateway.handle
    started, release = asyncio.Event(), asyncio.Event()

    async def respond(request):
        if request.url.path.startswith('/v1/signature/') and not started.is_set():
            started.set()
            await release.wait()
        return await original(request)

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(max_cache_entries=1) as client:
        first = await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        cancelled = asyncio.create_task(client.verify_response(first.id))
        await started.wait()
        continuing = asyncio.create_task(client.verify_response(first.id))
        await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        try:
            if cancel_all:
                continuing.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await continuing
                next_completion = await client.chat.completions.create(
                    model=MODEL, messages=MESSAGES
                )
                assert (
                    await client.verify_response(next_completion.id)
                ).id == next_completion.id
            else:
                release.set()
                assert (await continuing).id == first.id
        finally:
            release.set()
            await asyncio.gather(continuing, return_exceptions=True)
    assert gateway.signature_requests == 1


@pytest.mark.parametrize('eviction', ['count', 'bytes', 'expiry'])
async def test_eviction_preserves_inflight_verification(monkeypatch, eviction):
    gateway = Gateway()
    original = gateway.handle
    started, release = asyncio.Event(), asyncio.Event()

    async def respond(request):
        if request.url.path.startswith('/v1/signature/'):
            started.set()
            await release.wait()
        return await original(request)

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    options = {
        'count': {'max_cache_entries': 1},
        'bytes': {'max_receipt_cache_bytes': 512},
        'expiry': {'response_cache_time_to_live_ms': 20},
    }[eviction]
    async with gateway.client(e2ee=False, **options) as client:
        first = await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        verification = asyncio.create_task(client.verify_response(first.id))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            if eviction == 'expiry':
                await asyncio.sleep(0.04)
            else:
                second = await client.chat.completions.create(
                    model=MODEL, messages=MESSAGES
                )
                code = (
                    'api.invalid_input'
                    if eviction == 'count'
                    else 'api.completion_not_found'
                )
                with pytest.raises(ApiError, match=code):
                    await client.verify_response(second.id)
            with pytest.raises(ApiError, match='api.completion_not_found'):
                await client.verify_response(first.id)
            release.set()
            assert (await verification).id == first.id
            if eviction != 'count':
                second = await client.chat.completions.create(
                    model=MODEL, messages=MESSAGES
                )
            assert (await client.verify_response(second.id)).id == second.id
        finally:
            release.set()
            await asyncio.gather(verification, return_exceptions=True)


async def test_finished_verification_releases_bytes_before_its_done_callbacks(
    monkeypatch, gateway
):
    gateway.install(monkeypatch)
    started, release, completed = asyncio.Event(), asyncio.Event(), asyncio.Event()
    async with gateway.client(e2ee=False, max_receipt_cache_bytes=512) as client:
        original = client._verify_record

        async def verify(id, record):
            started.set()
            await release.wait()
            result = await original(id, record)
            completed.set()
            return result

        monkeypatch.setattr(client, '_verify_record', verify)
        first = await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        verification = asyncio.create_task(client.verify_response(first.id))
        try:
            await started.wait()
            await client.chat.completions.create(model=MODEL, messages=MESSAGES)

            async def send_next():
                # Wake before the completed verification's done callbacks.
                await completed.wait()
                return await client.chat.completions.create(
                    model=MODEL, messages=MESSAGES
                )

            next_completion = asyncio.create_task(send_next())
            release.set()
            third, verified = await asyncio.gather(next_completion, verification)
            assert verified.id == first.id
            assert (await client.verify_response(third.id)).id == third.id
        finally:
            release.set()
            await verification


async def test_close_awaits_evicted_verification_cleanup(monkeypatch):
    gateway = Gateway()
    original = gateway.handle
    started, cancelled, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    cleaned = asyncio.Event()

    async def respond(request):
        if request.url.path.startswith('/v1/signature/'):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
                await release.wait()
                cleaned.set()
        return await original(request)

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    client = gateway.client(e2ee=False, max_cache_entries=1)
    verification = close_task = None
    try:
        first = await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        verification = asyncio.create_task(client.verify_response(first.id))
        await asyncio.wait_for(started.wait(), timeout=1)
        await client.chat.completions.create(model=MODEL, messages=MESSAGES)
        close_task = asyncio.create_task(client.aclose())
        await asyncio.wait_for(cancelled.wait(), timeout=1)
        assert not close_task.done()
        release.set()
        await asyncio.wait_for(close_task, timeout=1)
        assert cleaned.is_set()
        with pytest.raises(asyncio.CancelledError):
            await verification
    finally:
        release.set()
        if close_task is not None:
            await close_task
        await client.aclose()
        if verification is not None:
            await asyncio.gather(verification, return_exceptions=True)


@pytest.mark.parametrize('replace_id', [False, True])
async def test_evicted_stream_reserves_bytes_until_verification_finishes(
    monkeypatch, replace_id
):
    gateway = Gateway()
    gateway.response_content = 'x' * 8192
    original = gateway.handle
    gates = {}
    replacement_id = None

    async def respond(request):
        gate = gates.get(request.url.path.removeprefix('/v1/signature/'))
        if gate is not None:
            started, release = gate
            started.set()
            await release.wait()
        response = await original(request)
        if replacement_id is not None and request.url.path == '/v1/chat/completions':
            completion = json.loads(await response.aread())
            completion['id'] = replacement_id
            return httpx.Response(200, json=completion)
        return response

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(e2ee=False, max_receipt_cache_bytes=10_000) as client:
        first_started, first_release = asyncio.Event(), asyncio.Event()
        verifying_first = None
        if not replace_id:
            first = await client.chat.completions.create(model=MODEL, messages=MESSAGES)
            gates[first.id] = first_started, first_release
            verifying_first = asyncio.create_task(client.verify_response(first.id))
        verifying_stream = None
        stream_started, stream_release = asyncio.Event(), asyncio.Event()
        tail_gate = asyncio.Event()
        gateway.tail_gate = tail_gate
        try:
            if verifying_first is not None:
                await asyncio.wait_for(first_started.wait(), timeout=1)
            stream = await client.chat.completions.create(
                model=MODEL, messages=MESSAGES, stream=True
            )
            chunks = [chunk async for chunk in stream]
            stream_id = chunks[0].id
            gates[stream_id] = stream_started, stream_release
            verifying_stream = asyncio.create_task(client.verify_response(stream_id))
            await asyncio.sleep(0)
            gateway.tail_gate = None
            if replace_id:
                replacement_id = stream_id
                await client.chat.completions.create(model=MODEL, messages=MESSAGES)
                replacement_id = None
            tail_gate.set()
            await asyncio.wait_for(stream_started.wait(), timeout=1)
            if replace_id:
                gates.pop(stream_id)
                with pytest.raises(ApiError, match='api.completion_not_found'):
                    await client.verify_response(stream_id)
            first_release.set()
            if verifying_first is not None:
                assert (await verifying_first).id == first.id

            third = await client.chat.completions.create(model=MODEL, messages=MESSAGES)
            with pytest.raises(ApiError, match='api.completion_not_found'):
                await client.verify_response(third.id)
            stream_release.set()
            assert (await verifying_stream).id == stream_id
            fourth = await client.chat.completions.create(
                model=MODEL, messages=MESSAGES
            )
            assert (await client.verify_response(fourth.id)).id == fourth.id
        finally:
            tail_gate.set()
            first_release.set()
            stream_release.set()
            if verifying_first is not None:
                await verifying_first
            if verifying_stream is not None:
                await verifying_stream


@pytest.mark.parametrize('oversized', [False, True])
@pytest.mark.parametrize('interface', ['send', 'openai'])
async def test_error_response_uses_body_limit_without_receipt_retention(
    monkeypatch, oversized, interface
):
    gateway = Gateway()
    original = gateway.handle
    closed = asyncio.Event()
    consumed = 0

    class ErrorStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            nonlocal consumed
            for _ in range(5 if oversized else 1):
                consumed += 1
                yield b'x' * 512

        async def aclose(self):
            closed.set()

    async def respond(request):
        if request.url.path == '/v1/chat/completions':
            return httpx.Response(400, stream=ErrorStream())
        return await original(request)

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(
        e2ee=False, max_body_bytes=1024, max_receipt_cache_bytes=128
    ) as client:
        if interface == 'send':
            response = await client.send(
                httpx.Request(
                    'POST',
                    BASE_URL + 'chat/completions',
                    json={'model': MODEL, 'messages': MESSAGES},
                )
            )
            if oversized:
                with pytest.raises(ApiError, match='api.body_too_large'):
                    await response.aread()
            else:
                assert await response.aread() == b'x' * 512
        else:
            # OpenAI wraps transport/body errors; inspect its original cause.
            async with AsyncOpenAI(
                api_key='test-key',
                base_url=BASE_URL,
                http_client=client.http_client,
                max_retries=0,
            ) as openai:
                if oversized:
                    with pytest.raises(APIConnectionError) as failure:
                        await openai.chat.completions.create(
                            model=MODEL, messages=MESSAGES
                        )
                    assert isinstance(failure.value.__cause__, ApiError)
                    assert failure.value.__cause__.failure.code == 'api.body_too_large'
                else:
                    with pytest.raises(BadRequestError) as failure:
                        await openai.chat.completions.create(
                            model=MODEL, messages=MESSAGES
                        )
                    assert failure.value.response.content == b'x' * 512
        assert consumed == (3 if oversized else 1)
        assert not client._responses
    assert closed.is_set()


async def test_signed_sse_tail_is_body_bounded(monkeypatch):
    gateway = Gateway()
    original = gateway.handle
    release = asyncio.Event()

    async def respond(request):
        response = await original(request)
        if request.url.path != '/v1/chat/completions':
            return response
        wire = await response.aread()

        class OversizedTail(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield wire
                await release.wait()
                yield b': ' + b'x' * 8192 + b'\n\n'

        return httpx.Response(200, headers=response.headers, stream=OversizedTail())

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(max_body_bytes=4096) as client:
        stream = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        chunks = [chunk async for chunk in stream]
        verification = asyncio.create_task(client.verify_response(chunks[0].id))
        await asyncio.sleep(0)
        release.set()
        with pytest.raises(ApiError, match='api.body_too_large'):
            await verification


async def test_pending_preflights_share_work_at_capacity(monkeypatch, gateway):
    original = gateway.handle
    started, release = asyncio.Event(), asyncio.Event()

    async def respond(request):
        if request.url.path == '/v1/attestation/report':
            started.set()
            await release.wait()
        return await original(request)

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(max_cache_entries=1) as client:
        first = asyncio.create_task(client.verify(MODEL))
        await started.wait()
        second = asyncio.create_task(client.verify(MODEL))
        with pytest.raises(ApiError, match='api.invalid_input'):
            await client.verify('different-model')
        release.set()
        await asyncio.gather(first, second)
        assert gateway.gateway_requests == 1


async def test_completed_preflight_does_not_occupy_capacity(monkeypatch, gateway):
    gateway.install(monkeypatch)
    completed = asyncio.Event()
    async with gateway.client(max_cache_entries=1) as client:
        original = client._create_session

        async def create(model):
            session = await original(model)
            completed.set()
            return session

        monkeypatch.setattr(client, '_create_session', create)

        async def verify_next():
            # Wake before the completed task's cache callback gets its turn.
            await completed.wait()
            return await client.verify('next-model')

        await asyncio.gather(client.verify(MODEL), verify_next())
    assert gateway.gateway_requests == 2


async def test_cancelled_preflight_occupies_capacity_until_cleanup_finishes(
    monkeypatch, gateway
):
    original = gateway.handle
    started, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    finished = asyncio.Event()

    async def respond(request):
        if request.url.path == '/v1/attestation/report' and not started.is_set():
            asyncio.current_task().add_done_callback(lambda _: finished.set())
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaning.set()
                await release.wait()
        return await original(request)

    monkeypatch.setattr(gateway, 'handle', respond)
    gateway.install(monkeypatch)
    async with gateway.client(max_cache_entries=1) as client:
        first = asyncio.create_task(client.verify(MODEL))
        await started.wait()
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        try:
            await cleaning.wait()
            with pytest.raises(ApiError, match='api.invalid_input'):
                await client.verify('different-model')
        finally:
            release.set()
            await finished.wait()
        await client.verify('different-model')
    assert gateway.gateway_requests == 1


async def test_abandoned_preflight_completion_cannot_remove_its_replacement(
    monkeypatch, gateway
):
    gateway.install(monkeypatch)
    started, cancelled = asyncio.Event(), asyncio.Event()
    finish_old, finish_new = asyncio.Event(), asyncio.Event()
    old_finished, new_started = asyncio.Event(), asyncio.Event()
    calls = 0
    async with gateway.client(max_cache_entries=2) as client:
        original = client._create_session

        async def create(model):
            nonlocal calls
            calls += 1
            if calls == 1:
                asyncio.current_task().add_done_callback(lambda _: old_finished.set())
                started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    cancelled.set()
                    # Simulate a transport completing during cancellation cleanup.
                    await finish_old.wait()
            else:
                new_started.set()
                await finish_new.wait()
            return await original(model)

        monkeypatch.setattr(client, '_create_session', create)
        first = asyncio.create_task(client.verify(MODEL))
        await started.wait()
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        try:
            async with asyncio.timeout(1):
                await cancelled.wait()
            replacement = asyncio.create_task(client.verify(MODEL))
            await asyncio.wait_for(new_started.wait(), timeout=1)
            finish_old.set()
            await asyncio.wait_for(old_finished.wait(), timeout=1)
            shared = asyncio.create_task(client.verify(MODEL))
            finish_new.set()
            assert await replacement is await shared
            assert calls == 2
        finally:
            finish_old.set()
            finish_new.set()
