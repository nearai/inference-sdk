from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from urllib.parse import parse_qs, urlsplit

import pytest

from verifiable_ai_sdk import (
    ApiError,
    CompletionSignature,
    SigningIdentity,
    fetch_completion_signature,
    fetch_gateway_attestation,
    fetch_model_attestation_for_signature,
    fetch_model_attestations,
    find_model_attestation_for_signature,
    lookup_completion_signature,
)
from verifiable_ai_sdk.core import cloud_api
from verifiable_ai_sdk.utils.fetch import FetchResponse


SIGNING_ADDRESS = f'0x{"22" * 20}'
API_KEY = 'test'
BASE_URL = 'https://cloud.example/v1'


CloudApiResponder = Callable[[str, Mapping[str, str]], Awaitable[FetchResponse]]


def use_fake_cloud_api_fetch(
    monkeypatch: pytest.MonkeyPatch,
    responder: CloudApiResponder,
) -> None:
    async def fake_default_fetch(
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        **_: object,
    ) -> FetchResponse:
        assert headers is not None
        return await responder(url, headers)

    monkeypatch.setattr(cloud_api, 'default_fetch', fake_default_fetch)


def cloud_attestation(nonce: str, **overrides: object) -> dict[str, object]:
    return {
        'request_nonce': nonce,
        'signing_algo': 'ecdsa',
        'signing_address': SIGNING_ADDRESS,
        'intel_quote': 'aa',
        'event_log': [],
        'info': {'tcb_info': {'app_compose': '{}'}},
        'tls_cert_fingerprint': '33' * 32,
        **overrides,
    }


def model_signature() -> CompletionSignature:
    return CompletionSignature(
        kind='provider_tee',
        signed_text='canonical-model:request:response',
        signature='00',
        signer=SigningIdentity(signing_algo='ecdsa', signing_address=SIGNING_ADDRESS),
    )


async def test_model_helpers_request_fresh_evidence_and_select_signer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    async def fake_fetch(url: str, headers: Mapping[str, str]) -> FetchResponse:
        calls.append((url, dict(headers)))
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'model_attestations': [
                        cloud_attestation(nonce, report_data='44' * 64)
                    ]
                }
            ).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, fake_fetch)

    fetched = await fetch_model_attestations(
        API_KEY,
        'canonical-model',
        signing_algo='ecdsa',
        signing_address=SIGNING_ADDRESS,
        base_url=BASE_URL,
    )
    selected = find_model_attestation_for_signature(
        fetched.attestations, model_signature()
    )

    assert selected.nonce == fetched.nonce
    assert selected.app_compose == '{}'
    assert len(calls) == 1
    url, headers = calls[0]
    query = parse_qs(urlsplit(url).query)
    assert urlsplit(url).geturl().startswith(f'{BASE_URL}/attestation/report?')
    assert query['model'] == ['canonical-model']
    assert query['provider'] == ['near']
    assert query['nonce'] == [fetched.nonce]
    assert query['signing_algo'] == ['ecdsa']
    assert query['signing_address'] == [SIGNING_ADDRESS]
    assert headers['authorization'] == 'Bearer test'
    assert headers['x-no-aliasing'] == 'true'


async def test_model_helpers_match_equivalent_hex_nonce_and_signer_formats(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_fetch(url: str, _: Mapping[str, str]) -> FetchResponse:
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        wire_nonce = f'0X{nonce.upper()}'
        wire_signing_address = f'0X{SIGNING_ADDRESS.removeprefix("0x").upper()}'
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'model_attestations': [
                        cloud_attestation(
                            wire_nonce,
                            signing_address=wire_signing_address,
                        )
                    ]
                }
            ).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, fake_fetch)

    fetched = await fetch_model_attestations(API_KEY, 'canonical-model')
    selected = find_model_attestation_for_signature(
        fetched.attestations, model_signature()
    )

    assert selected.nonce.startswith('0X')
    assert selected.signer.signing_address.startswith('0X')


async def test_model_helper_decodes_serialized_tcb_info(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_fetch(url: str, _: Mapping[str, str]) -> FetchResponse:
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'model_attestations': [
                        cloud_attestation(
                            nonce,
                            info={
                                'tcb_info': json.dumps(
                                    {'app_compose': '{"services": {}}'}
                                )
                            },
                        )
                    ]
                }
            ).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, fake_fetch)

    fetched = await fetch_model_attestations(
        API_KEY,
        'canonical-model',
    )

    assert fetched.attestations[0].app_compose == '{"services": {}}'


async def test_fetch_model_attestation_for_signature_adds_signer_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen_url = ''

    async def fake_fetch(url: str, _: Mapping[str, str]) -> FetchResponse:
        nonlocal seen_url
        seen_url = url
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'model_attestations': [
                        cloud_attestation(nonce, report_data='44' * 64)
                    ]
                }
            ).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, fake_fetch)

    fetched = await fetch_model_attestation_for_signature(
        API_KEY,
        'canonical-model',
        model_signature(),
    )
    assert fetched.attestation.signer.signing_address == SIGNING_ADDRESS
    query = parse_qs(urlsplit(seen_url).query)
    assert query['signing_algo'] == ['ecdsa']
    assert query['signing_address'] == [SIGNING_ADDRESS]


async def test_gateway_helper_requests_tls_aware_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen_url = ''

    async def fake_gateway_fetch(
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        **_: object,
    ) -> FetchResponse:
        nonlocal seen_url
        assert headers is not None
        seen_url = url
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'gateway_attestation': cloud_attestation(
                        nonce,
                        signing_algo='ed25519',
                        signing_address='55' * 32,
                        report_data='00' * 64,
                    )
                }
            ).encode(),
            peer_spki_fingerprint='33' * 32,
        )

    monkeypatch.setattr(cloud_api, 'default_fetch', fake_gateway_fetch)
    fetched = await fetch_gateway_attestation(
        API_KEY,
        signing_algo='ed25519',
    )

    assert fetched.attestation.nonce == fetched.client_binding.nonce
    assert fetched.client_binding.peer_spki_fingerprint == '33' * 32
    query = parse_qs(urlsplit(seen_url).query)
    assert query['include_tls_fingerprint'] == ['true']
    assert query['signing_algo'] == ['ed25519']


async def test_gateway_helper_requires_tls_fingerprint_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_gateway_fetch(
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        **_: object,
    ) -> FetchResponse:
        assert headers is not None
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'gateway_attestation': cloud_attestation(
                        nonce,
                        signing_algo='ed25519',
                        signing_address='55' * 32,
                        tls_cert_fingerprint=None,
                        report_data='00' * 64,
                    )
                }
            ).encode(),
        )

    monkeypatch.setattr(cloud_api, 'default_fetch', fake_gateway_fetch)

    with pytest.raises(ApiError) as malformed:
        await fetch_gateway_attestation(API_KEY)

    assert malformed.value.failure.code == 'api.invalid_response'
    assert (
        malformed.value.failure.details['path']
        == 'gateway_attestation.tls_cert_fingerprint'
    )


async def test_completion_signature_lookup_preserves_unavailable_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unavailable(_: str, __: Mapping[str, str]) -> FetchResponse:
        return FetchResponse(
            status=200,
            body=json.dumps({'error_code': 'pending', 'message': 'wait'}).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, unavailable)

    lookup = await lookup_completion_signature(
        API_KEY,
        'completion-id',
    )
    assert lookup.status == 'unavailable'
    assert lookup.unavailable is not None
    assert lookup.unavailable.error_code == 'pending'
    with pytest.raises(ApiError) as unavailable_error:
        await fetch_completion_signature(
            API_KEY,
            'completion-id',
        )
    assert (
        unavailable_error.value.failure.code == 'api.completion_signature_unavailable'
    )
    assert unavailable_error.value.failure.details == {'providerErrorCode': 'pending'}


async def test_completion_signature_lookup_requires_signature_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def missing_kind(_: str, __: Mapping[str, str]) -> FetchResponse:
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'text': 'request:response',
                    'signature': '00',
                    'signing_address': SIGNING_ADDRESS,
                    'signing_algo': 'ecdsa',
                }
            ).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, missing_kind)

    with pytest.raises(ApiError) as malformed:
        await fetch_completion_signature(
            API_KEY,
            'completion-id',
        )
    assert malformed.value.failure.code == 'api.invalid_response'


async def test_model_report_count_and_nonce_are_checked_before_returning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def two_attestations(url: str, _: Mapping[str, str]) -> FetchResponse:
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'model_attestations': [
                        cloud_attestation(nonce),
                        cloud_attestation(nonce),
                    ]
                }
            ).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, two_attestations)

    with pytest.raises(ApiError) as count_error:
        await fetch_model_attestations(
            API_KEY,
            'canonical-model',
        )
    assert count_error.value.failure.code == 'api.unexpected_model_attestation_count'

    async def wrong_nonce(url: str, _: Mapping[str, str]) -> FetchResponse:
        _ = url
        return FetchResponse(
            status=200,
            body=json.dumps(
                {'model_attestations': [cloud_attestation('44' * 32)]}
            ).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, wrong_nonce)

    with pytest.raises(ApiError) as nonce_error:
        await fetch_model_attestations(
            API_KEY,
            'canonical-model',
        )
    assert nonce_error.value.failure.code == 'api.nonce_mismatch'


async def test_redirect_response_is_not_a_successful_cloud_api_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def redirect(_: str, __: Mapping[str, str]) -> FetchResponse:
        return FetchResponse(status=302, body=b'{}')

    use_fake_cloud_api_fetch(monkeypatch, redirect)

    with pytest.raises(ApiError) as raised:
        await fetch_model_attestations(
            API_KEY,
            'canonical-model',
        )

    assert raised.value.failure.code == 'api.http_status'
    assert raised.value.failure.details == {
        'resource': 'model_attestation',
        'status': 302,
    }


async def test_non_utf8_success_response_is_an_api_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def non_utf8(_: str, __: Mapping[str, str]) -> FetchResponse:
        return FetchResponse(status=200, body=b'\xff')

    use_fake_cloud_api_fetch(monkeypatch, non_utf8)

    with pytest.raises(ApiError) as raised:
        await fetch_model_attestations(API_KEY, 'canonical-model')

    assert raised.value.failure.code == 'api.invalid_json'
    assert raised.value.failure.details == {'resource': 'model_attestation'}
