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
from eth_account.messages import encode_defunct
from openai import AsyncOpenAI

from nearai_inference_sdk import (
    ApiError,
    AttestationVerificationResult,
    AttestationVerifiers,
    GatewayVerificationOptions,
    ModelAttestationVerifiers,
    ModelVerificationOptions,
    VerificationError,
)
from nearai_inference_sdk.core import inference_client
from nearai_inference_sdk.utils.errors import api_failure

from .support.attestation import APP_COMPOSE
from .support.gateway import BASE_URL, MESSAGES, MODEL, ChunkStream, Gateway
from .support.gateway_ohttp import ObliviousGateway


@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
@pytest.mark.parametrize('kind', ['provider_tee', 'gateway'])
@pytest.mark.parametrize('e2ee', [False, True], ids=['plaintext', 'encrypted'])
async def test_chat_json_and_stream_receipts_keep_their_preflight_snapshot(
    monkeypatch, signing_algo, kind, e2ee
):
    gateway = Gateway(signing_algo, kind)
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
        preflight = await client.verify(MODEL)
        assert len({item.deployment.app_compose for item in preflight.models}) == 2
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        assert completion.choices[0].message.content == 'Hello back'
        stream = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES, stream=True
        )
        chunks = [chunk async for chunk in stream]
        assert (
            ''.join(chunk.choices[0].delta.content or '' for chunk in chunks)
            == 'Hello back'
        )
        assert await client.verify(MODEL) is preflight
        assert gateway.model_requests == [MODEL]

        now = 2
        gateway.model_report_count = 3
        refreshed = await client.verify(MODEL)
        assert refreshed is not preflight
        assert len(refreshed.models) == 3
        for completion_id in (completion.id, chunks[0].id):
            receipt = await client.verify_response(completion_id)
            assert receipt.id == completion_id
            assert receipt.signature_kind == kind
            assert await client.verify_response(completion_id) is receipt
            if kind == 'provider_tee':
                assert receipt.attestations == preflight.models
                assert all(
                    actual is expected
                    for actual, expected in zip(
                        receipt.attestations, preflight.models, strict=True
                    )
                )
                assert receipt.attestation is preflight.models[0]
            else:
                assert receipt.attestation is preflight.gateway
                assert not hasattr(receipt, 'attestations')

    assert gateway.plaintexts == ['Hello', 'Hello']
    assert gateway.gateway_requests == 2
    assert gateway.model_requests == [MODEL, MODEL]
    assert gateway.signature_requests == 2
    assert all(
        ('x-client-pub-key' in request.headers) == e2ee
        and (b'Hello' not in request.content) == e2ee
        for request in gateway.completion_requests
    )


@pytest.fixture(params=['direct', 'ohttp'])
def gateway(request):
    if request.param == 'ohttp':
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
            no_public_key = other.attestation(nonce)
            no_public_key.pop('signing_public_key')
            reports.insert(0, no_public_key)
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
        assert preflight.models[0].signing_public_key is None
        assert [report.signer.signing_address for report in preflight.models] == [
            other.address,
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
            assert receipt.attestations == (preflight.models[1], preflight.models[3])
            assert receipt.attestation is preflight.models[1]


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


async def test_preflight_awaits_gateway_then_model_verifier_then_policy(monkeypatch):
    gateway = Gateway()
    gateway.install(monkeypatch)
    release_gateway = asyncio.Event()
    gateway_started = asyncio.Event()
    model_verified = asyncio.Event()
    release_model = asyncio.Event()
    checked = []

    async def verify_gateway_quote(quote):
        gateway_started.set()
        await release_gateway.wait()
        return gateway.quotes[quote]

    async def verify_model_deployment(deployment):
        model_verified.set()
        await release_model.wait()
        checked.append(('verifier', deployment))

    def check_deployment(model, deployment):
        assert model == MODEL
        checked.append(('policy', deployment))

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
        deployment_policy=check_deployment,
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
        async with asyncio.timeout(1):
            await model_verified.wait()
        assert checked == []
        assert gateway.completion_requests == []
        assert not preflight.done() and not chat.done()
        release_model.set()
        await preflight
        assert [phase for phase, _ in checked] == ['verifier', 'policy']
        assert checked[0][1] is checked[1][1]
        completion = await chat
        await client.verify_response(completion.id)

    assert gateway.gateway_requests == 1
    assert gateway.model_requests == [MODEL]
    assert len(gateway.completion_requests) == 1


async def test_cancelling_one_receipt_waiter_preserves_shared_verification(
    monkeypatch, gateway
):
    gateway.install(monkeypatch)
    entered = asyncio.Event()
    release = asyncio.Event()
    async with gateway.client() as client:
        completion = await client.chat.completions.create(
            model=MODEL, messages=MESSAGES
        )
        record = client._responses[completion.id]
        api = record.session.attestation_client
        original = api.fetch_completion_signature

        async def fetch_signature(*args, **kwargs):
            entered.set()
            await release.wait()
            return await original(*args, **kwargs)

        monkeypatch.setattr(api, 'fetch_completion_signature', fetch_signature)
        first = asyncio.create_task(client.verify_response(completion.id))
        async with asyncio.timeout(1):
            await entered.wait()
        second = asyncio.create_task(client.verify_response(completion.id))
        await asyncio.sleep(0)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert not second.done()
        release.set()
        receipt = await second
        assert await client.verify_response(completion.id) is receipt
        assert receipt.id == completion.id
        assert record.request_body == b''
        assert record.response_body is None and record.session is None
    assert gateway.signature_requests == 1
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
