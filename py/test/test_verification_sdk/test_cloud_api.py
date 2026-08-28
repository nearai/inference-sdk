from __future__ import annotations

import json
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest

from verification_sdk import (
    ApiError,
    CompletionSignature,
    FetchCompletionSignatureInput,
    FetchGatewayAttestationInput,
    FetchModelAttestationForSignatureInput,
    FetchModelAttestationsInput,
    FindModelAttestationForSignatureInput,
    NearAiCloudOptions,
    NearAiCloudResponse,
    SigningIdentity,
    VerificationError,
    fetch_completion_signature,
    fetch_gateway_attestation,
    fetch_model_attestation_for_signature,
    fetch_model_attestations,
    find_model_attestation_for_signature,
    lookup_completion_signature,
)


SIGNING_ADDRESS = f'0x{"22" * 20}'


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


async def test_model_helpers_request_fresh_evidence_and_select_signer() -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    async def fake_fetch(url: str, headers: dict[str, str]) -> NearAiCloudResponse:
        calls.append((url, dict(headers)))
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return NearAiCloudResponse(
            status=200,
            body=json.dumps(
                {
                    'model_attestations': [
                        cloud_attestation(nonce, report_data='44' * 64)
                    ]
                }
            ),
        )

    cloud = NearAiCloudOptions(api_key='test', fetch=fake_fetch)
    fetched = await fetch_model_attestations(
        cloud,
        FetchModelAttestationsInput(
            model='canonical-model',
            signing_algo='ecdsa',
            signing_address=SIGNING_ADDRESS,
        ),
    )
    selected = find_model_attestation_for_signature(
        input=FindModelAttestationForSignatureInput(
            attestations=fetched.attestations, signature=model_signature()
        )
    )

    assert selected.nonce == fetched.nonce
    assert selected.app_compose == '{}'
    assert len(calls) == 1
    url, headers = calls[0]
    query = parse_qs(urlsplit(url).query)
    assert query['model'] == ['canonical-model']
    assert query['provider'] == ['near']
    assert query['nonce'] == [fetched.nonce]
    assert query['signing_algo'] == ['ecdsa']
    assert query['signing_address'] == [SIGNING_ADDRESS]
    assert headers['authorization'] == 'Bearer test'
    assert headers['x-no-aliasing'] == 'true'

    invalid_signature = replace(
        model_signature(),
        signer=SigningIdentity(signing_algo='ecdsa', signing_address='00'),
    )
    with pytest.raises(VerificationError) as malformed_signature:
        find_model_attestation_for_signature(
            input=FindModelAttestationForSignatureInput(
                attestations=fetched.attestations,
                signature=invalid_signature,
            )
        )
    assert malformed_signature.value.failure.details['field'] == (
        'signature.signer.signing_address'
    )

    invalid_candidate = replace(
        fetched.attestations[0],
        signer=SigningIdentity(signing_algo='ecdsa', signing_address='00'),
    )
    with pytest.raises(VerificationError) as malformed_candidate:
        find_model_attestation_for_signature(
            input=FindModelAttestationForSignatureInput(
                attestations=(invalid_candidate,),
                signature=model_signature(),
            )
        )
    assert malformed_candidate.value.failure.details['field'] == (
        'attestations[0].signer.signing_address'
    )


async def test_fetch_model_attestation_for_signature_adds_signer_filters() -> None:
    seen_url = ''

    async def fake_fetch(url: str, _: dict[str, str]) -> NearAiCloudResponse:
        nonlocal seen_url
        seen_url = url
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return NearAiCloudResponse(
            status=200,
            body=json.dumps(
                {
                    'model_attestations': [
                        cloud_attestation(nonce, report_data='44' * 64)
                    ]
                }
            ),
            peer_spki_fingerprint='33' * 32,
        )

    fetched = await fetch_model_attestation_for_signature(
        NearAiCloudOptions(api_key='test', fetch=fake_fetch),
        FetchModelAttestationForSignatureInput(
            model='canonical-model', signature=model_signature()
        ),
    )
    assert fetched.attestation.signer.signing_address == SIGNING_ADDRESS
    query = parse_qs(urlsplit(seen_url).query)
    assert query['signing_algo'] == ['ecdsa']
    assert query['signing_address'] == [SIGNING_ADDRESS]


async def test_gateway_helper_requests_tls_aware_evidence() -> None:
    seen_url = ''

    async def fake_fetch(url: str, _: dict[str, str]) -> NearAiCloudResponse:
        nonlocal seen_url
        seen_url = url
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return NearAiCloudResponse(
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
            ),
            peer_spki_fingerprint='33' * 32,
        )

    fetched = await fetch_gateway_attestation(
        NearAiCloudOptions(api_key='test', fetch=fake_fetch),
        FetchGatewayAttestationInput(signing_algo='ed25519'),
    )
    assert fetched.attestation.nonce == fetched.nonce
    assert fetched.peer_spki_fingerprint == '33' * 32
    query = parse_qs(urlsplit(seen_url).query)
    assert query['include_tls_fingerprint'] == ['true']
    assert query['signing_algo'] == ['ed25519']


async def test_signature_lookup_preserves_unavailable_and_requires_kind() -> None:
    async def unavailable(_: str, __: dict[str, str]) -> NearAiCloudResponse:
        return NearAiCloudResponse(
            status=200, body=json.dumps({'error_code': 'pending', 'message': 'wait'})
        )

    cloud = NearAiCloudOptions(api_key='test', fetch=unavailable)
    lookup = await lookup_completion_signature(
        cloud, FetchCompletionSignatureInput(completion_id='completion-id')
    )
    assert lookup.status == 'unavailable'
    assert lookup.unavailable is not None
    assert lookup.unavailable.error_code == 'pending'
    with pytest.raises(VerificationError) as unavailable_error:
        await fetch_completion_signature(
            cloud, FetchCompletionSignatureInput(completion_id='completion-id')
        )
    assert unavailable_error.value.code == 'signature.unavailable'

    async def missing_kind(_: str, __: dict[str, str]) -> NearAiCloudResponse:
        return NearAiCloudResponse(
            status=200,
            body=json.dumps(
                {
                    'text': 'request:response',
                    'signature': '00',
                    'signing_address': SIGNING_ADDRESS,
                    'signing_algo': 'ecdsa',
                }
            ),
        )

    with pytest.raises(ApiError) as malformed:
        await fetch_completion_signature(
            NearAiCloudOptions(api_key='test', fetch=missing_kind),
            FetchCompletionSignatureInput(completion_id='completion-id'),
        )
    assert malformed.value.code == 'api.invalid_response'


async def test_model_report_count_and_nonce_are_checked_before_returning() -> None:
    async def two_attestations(url: str, _: dict[str, str]) -> NearAiCloudResponse:
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return NearAiCloudResponse(
            status=200,
            body=json.dumps(
                {
                    'model_attestations': [
                        cloud_attestation(nonce),
                        cloud_attestation(nonce),
                    ]
                }
            ),
        )

    with pytest.raises(ApiError) as count_error:
        await fetch_model_attestations(
            NearAiCloudOptions(api_key='test', fetch=two_attestations),
            FetchModelAttestationsInput(model='canonical-model'),
        )
    assert count_error.value.code == 'api.unexpected_model_attestation_count'

    async def wrong_nonce(url: str, _: dict[str, str]) -> NearAiCloudResponse:
        _ = url
        return NearAiCloudResponse(
            status=200,
            body=json.dumps({'model_attestations': [cloud_attestation('44' * 32)]}),
        )

    with pytest.raises(ApiError) as nonce_error:
        await fetch_model_attestations(
            NearAiCloudOptions(api_key='test', fetch=wrong_nonce),
            FetchModelAttestationsInput(model='canonical-model'),
        )
    assert nonce_error.value.code == 'api.nonce_mismatch'


async def test_model_report_data_must_be_omitted_or_a_string() -> None:
    async def null_report_data(url: str, _: dict[str, str]) -> NearAiCloudResponse:
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return NearAiCloudResponse(
            status=200,
            body=json.dumps(
                {'model_attestations': [cloud_attestation(nonce, report_data=None)]}
            ),
        )

    with pytest.raises(ApiError) as raised:
        await fetch_model_attestations(
            NearAiCloudOptions(api_key='test', fetch=null_report_data),
            FetchModelAttestationsInput(model='canonical-model'),
        )

    assert raised.value.code == 'api.invalid_response'
    assert raised.value.failure.details['path'] == 'model_attestations[0].report_data'


async def test_redirect_response_is_not_a_successful_cloud_api_response() -> None:
    async def redirect(_: str, __: dict[str, str]) -> NearAiCloudResponse:
        return NearAiCloudResponse(status=302, body='{}')

    with pytest.raises(ApiError) as raised:
        await fetch_model_attestations(
            NearAiCloudOptions(api_key='test', fetch=redirect),
            FetchModelAttestationsInput(model='canonical-model'),
        )

    assert raised.value.code == 'api.http_status'
    assert raised.value.failure.details == {
        'resource': 'model_attestation',
        'status': 302,
    }


async def test_cloud_response_status_must_be_an_integer() -> None:
    async def invalid_status(_: str, __: dict[str, str]) -> NearAiCloudResponse:
        return NearAiCloudResponse(status=True, body='{}')

    with pytest.raises(ApiError) as raised:
        await fetch_model_attestations(
            NearAiCloudOptions(api_key='test', fetch=invalid_status),
            FetchModelAttestationsInput(model='canonical-model'),
        )

    assert raised.value.code == 'api.invalid_response'
    assert raised.value.failure.details['path'] == 'model_attestation response.status'


@pytest.mark.parametrize(
    'base_url',
    ['https://example.com:bad/v1', 'https://:443/v1'],
)
async def test_invalid_base_url_is_rejected_before_a_cloud_request(
    base_url: str,
) -> None:
    calls = 0

    async def fake_fetch(_: str, __: dict[str, str]) -> NearAiCloudResponse:
        nonlocal calls
        calls += 1
        return NearAiCloudResponse(status=200, body='{}')

    with pytest.raises(VerificationError) as raised:
        await fetch_model_attestations(
            NearAiCloudOptions(api_key='test', base_url=base_url, fetch=fake_fetch),
            FetchModelAttestationsInput(model='canonical-model'),
        )

    assert raised.value.code == 'input.invalid'
    assert calls == 0


@pytest.mark.parametrize(
    ('cloud', 'field'),
    [
        (NearAiCloudOptions(api_key=1), 'api_key'),
        (NearAiCloudOptions(api_key='test', fetch=object()), 'fetch'),
    ],
)
async def test_invalid_cloud_options_raise_a_structured_input_error(
    cloud: NearAiCloudOptions,
    field: str,
) -> None:
    with pytest.raises(VerificationError) as raised:
        await fetch_model_attestations(
            cloud,
            FetchModelAttestationsInput(model='canonical-model'),
        )

    assert raised.value.code == 'input.invalid'
    assert raised.value.failure.details['field'] == field


async def test_cloud_transport_must_return_an_awaitable() -> None:
    def synchronous_fetch(_: str, __: dict[str, str]) -> NearAiCloudResponse:
        return NearAiCloudResponse(status=200, body='{}')

    with pytest.raises(VerificationError) as raised:
        await fetch_model_attestations(
            NearAiCloudOptions(api_key='test', fetch=synchronous_fetch),
            FetchModelAttestationsInput(model='canonical-model'),
        )

    assert raised.value.code == 'input.invalid'
    assert raised.value.failure.details['field'] == 'fetch'


async def test_cloud_helpers_reject_an_invalid_input_object() -> None:
    with pytest.raises(VerificationError) as raised:
        await fetch_model_attestations(NearAiCloudOptions(api_key='test'), None)

    assert raised.value.code == 'input.invalid'
    assert raised.value.failure.details['field'] == 'input'
