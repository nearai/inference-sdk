from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from urllib.parse import parse_qs, urlsplit

import pytest

from nearai_inference_sdk import (
    AttestationClient,
    ApiError,
    CompletionSignature,
    CompletionSignatureReference,
    MeasuredDeployment,
    RuntimeMeasurements,
    SigningIdentity,
    VerifiedModelAttestation,
    find_model_attestation_for_signature,
)
from nearai_inference_sdk.core import cloud_api
from nearai_inference_sdk.utils.fetch import FetchResponse


SIGNING_ADDRESS = f'0x{"22" * 20}'
API_KEY = 'test'
BASE_URL = 'https://cloud.example/v1'


CloudApiResponder = Callable[[str, Mapping[str, str]], Awaitable[FetchResponse]]


def cloud_client() -> AttestationClient:
    return AttestationClient(API_KEY, base_url=BASE_URL)


@pytest.mark.parametrize(
    ('base_url'),
    (
        pytest.param('not a URL', id='malformed'),
        pytest.param('/v1', id='relative'),
        pytest.param('ftp://cloud.example/v1', id='non-http'),
    ),
)
def test_client_rejects_invalid_base_urls_at_construction(base_url: str) -> None:
    with pytest.raises(ApiError) as raised:
        AttestationClient(API_KEY, base_url=base_url)

    assert raised.value.failure.code == 'api.invalid_input'
    assert raised.value.failure.details == {
        'field': 'base_url',
        'reason': 'invalid_url',
        'expected': 'an absolute HTTP(S) URL',
    }
    assert raised.value.retryable is False


async def test_client_rejects_an_invalid_api_key_before_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = 0

    async def fake_fetch(*_: object, **__: object) -> FetchResponse:
        nonlocal requests
        requests += 1
        raise AssertionError('invalid helper input must not make a request')

    monkeypatch.setattr(cloud_api, 'default_fetch', fake_fetch)
    client = AttestationClient('invalid\nheader', base_url=BASE_URL)

    with pytest.raises(ApiError) as raised:
        await client.fetch_completion_signature('completion-id')

    assert raised.value.failure.code == 'api.invalid_input'
    assert raised.value.failure.details == {
        'field': 'api_key',
        'reason': 'invalid_header_value',
        'expected': 'an HTTP header value',
    }
    assert requests == 0


@pytest.mark.parametrize('api_key', [None, API_KEY])
async def test_client_uses_custom_headers_and_prefers_an_explicit_api_key(
    monkeypatch: pytest.MonkeyPatch,
    api_key: str | None,
) -> None:
    async def fake_fetch(_: str, headers: Mapping[str, str]) -> FetchResponse:
        assert headers['authorization'] == (
            'Bearer test' if api_key is not None else 'Bearer aggregator-token'
        )
        assert headers['x-tenant'] == 'example'
        return completion_signature_response(
            signing_algo='ecdsa', kind='gateway', signing_address=SIGNING_ADDRESS
        )

    use_fake_cloud_api_fetch(monkeypatch, fake_fetch)
    client = AttestationClient(
        api_key,
        base_url=BASE_URL,
        headers={'Authorization': 'Bearer aggregator-token', 'X-Tenant': 'example'},
    )

    signature = await client.fetch_completion_signature('completion-id')

    assert signature.kind == 'gateway'


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


def verified_model_attestation_for_signer(
    signer: SigningIdentity,
) -> VerifiedModelAttestation:
    return VerifiedModelAttestation(
        signer=signer,
        tcb_status='UpToDate',
        advisory_ids=(),
        deployment=MeasuredDeployment(
            app_compose='{}',
            runtime_measurements=RuntimeMeasurements(),
        ),
        deployment_provenance='not_checked',
        gpu_evidence='not_provided',
    )


def completion_signature_response(
    *,
    signing_algo: str,
    kind: str,
    signing_address: str,
) -> FetchResponse:
    return FetchResponse(
        status=200,
        body=json.dumps(
            {
                'text': f'{kind}:request:response',
                'signature': 'aa',
                'signing_address': signing_address,
                'signing_algo': signing_algo,
                'signature_kind': kind,
            }
        ).encode(),
    )


async def test_model_helper_requests_fresh_evidence(
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
                        cloud_attestation(
                            nonce,
                            report_data='44' * 64,
                            signing_public_key='55' * 65,
                        ),
                        cloud_attestation(
                            nonce,
                            signing_address='33' * 20,
                            report_data='44' * 64,
                        ),
                    ]
                }
            ).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, fake_fetch)

    fetched = await cloud_client().fetch_model_attestations(
        'canonical-model',
        signing_algo='ecdsa',
        signing_address=SIGNING_ADDRESS,
    )
    assert tuple(
        attestation.signer.signing_address for attestation in fetched.attestations
    ) == (SIGNING_ADDRESS, '33' * 20)
    assert fetched.attestations[0].signing_public_key == '55' * 65
    assert fetched.attestations[1].signing_public_key is None
    assert len(calls) == 1
    url, headers = calls[0]
    query = parse_qs(urlsplit(url).query)
    assert urlsplit(url).geturl().startswith(f'{BASE_URL}/attestation/report?')
    assert query['model'] == ['canonical-model']
    assert query['provider'] == ['near']
    assert query['nonce'] == [fetched.client_binding.nonce]
    assert query['include_tls_fingerprint'] == ['false']
    assert query['signing_algo'] == ['ecdsa']
    assert query['signing_address'] == [SIGNING_ADDRESS]
    assert headers['authorization'] == 'Bearer test'
    assert headers['x-no-aliasing'] == 'true'


def test_model_selection_matches_equivalent_hex_signer_formats() -> None:
    verified = verified_model_attestation_for_signer(
        SigningIdentity(
            signing_algo='ecdsa',
            signing_address=f'0X{SIGNING_ADDRESS.removeprefix("0x").upper()}',
        )
    )
    selected = find_model_attestation_for_signature([verified], model_signature())

    assert selected is verified
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

    fetched = await cloud_client().fetch_model_attestations('canonical-model')

    assert tuple(attestation.app_compose for attestation in fetched.attestations) == (
        '{"services": {}}',
    )


@pytest.mark.parametrize('signing_algo', [None, 'ecdsa'])
async def test_gateway_helper_requests_spki_fingerprint_evidence(
    monkeypatch: pytest.MonkeyPatch,
    signing_algo: str | None,
) -> None:
    seen_url = ''
    capture_peer_spki: object | None = None

    async def fake_gateway_fetch(
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        **options: object,
    ) -> FetchResponse:
        nonlocal capture_peer_spki, seen_url
        assert headers is not None
        seen_url = url
        capture_peer_spki = options.get('_capture_peer_spki')
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        returned_algo = signing_algo or 'ed25519'
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'gateway_attestation': cloud_attestation(
                        nonce,
                        signing_algo=returned_algo,
                        signing_address=(
                            SIGNING_ADDRESS if returned_algo == 'ecdsa' else '55' * 32
                        ),
                        report_data='00' * 64,
                    )
                }
            ).encode(),
            peer_spki_fingerprint='33' * 32,
        )

    monkeypatch.setattr(cloud_api, 'default_fetch', fake_gateway_fetch)
    fetched = await cloud_client().fetch_gateway_attestation(
        signing_algo=signing_algo,
    )

    assert fetched.attestation.nonce == fetched.client_binding.nonce
    assert fetched.client_binding.spki_fingerprint == '33' * 32
    assert capture_peer_spki is True
    query = parse_qs(urlsplit(seen_url).query)
    assert urlsplit(seen_url).geturl().startswith(f'{BASE_URL}/attestation/report?')
    assert query['include_tls_fingerprint'] == ['true']
    if signing_algo is None:
        assert 'signing_algo' not in query
    else:
        assert query['signing_algo'] == [signing_algo]


async def test_gateway_helper_uses_signer_nonce_evidence_without_spki_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen_url = ''
    capture_peer_spki: object | None = None

    async def fake_gateway_fetch(
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        **options: object,
    ) -> FetchResponse:
        nonlocal capture_peer_spki, seen_url
        assert headers is not None
        seen_url = url
        capture_peer_spki = options.get('_capture_peer_spki')
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
    fetched = await cloud_client().fetch_gateway_attestation(
        include_spki_fingerprint=False,
    )

    assert fetched.attestation.spki_fingerprint is None
    assert capture_peer_spki is False
    assert parse_qs(urlsplit(seen_url).query)['include_tls_fingerprint'] == ['false']


async def test_gateway_helper_rejects_a_mismatched_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def wrong_nonce(_: str, __: Mapping[str, str]) -> FetchResponse:
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'gateway_attestation': cloud_attestation(
                        '44' * 32,
                        signing_algo='ed25519',
                        signing_address='55' * 32,
                        report_data='00' * 64,
                    )
                }
            ).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, wrong_nonce)

    with pytest.raises(ApiError) as raised:
        await cloud_client().fetch_gateway_attestation()

    assert raised.value.failure.code == 'api.nonce_mismatch'
    assert raised.value.failure.details == {'resource': 'gateway_attestation'}


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
        await cloud_client().fetch_gateway_attestation()

    assert malformed.value.failure.code == 'api.invalid_response'
    assert malformed.value.failure.details == {
        'path': 'gateway_attestation.tls_cert_fingerprint',
        'expected': 'present',
        'actual': 'missing',
    }


async def test_gateway_helper_rejects_spki_fingerprint_when_not_requested(
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
                        report_data='00' * 64,
                    )
                }
            ).encode(),
        )

    monkeypatch.setattr(cloud_api, 'default_fetch', fake_gateway_fetch)

    with pytest.raises(ApiError) as malformed:
        await cloud_client().fetch_gateway_attestation(
            include_spki_fingerprint=False,
        )

    assert malformed.value.failure.code == 'api.invalid_response'
    assert malformed.value.failure.details == {
        'path': 'gateway_attestation.tls_cert_fingerprint',
        'expected': 'missing',
        'actual': 'present',
    }


async def test_fetch_completion_signature_maps_unavailable_response_to_api_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unavailable(_: str, __: Mapping[str, str]) -> FetchResponse:
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'error_code': 'STREAM_DISCONNECTED',
                    'message': 'Verification not available due to disconnection.',
                }
            ).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, unavailable)

    with pytest.raises(ApiError) as unavailable_error:
        await cloud_client().fetch_completion_signature('completion-id')
    assert (
        unavailable_error.value.failure.code == 'api.completion_signature_unavailable'
    )
    assert unavailable_error.value.failure.details == {
        'providerErrorCode': 'STREAM_DISCONNECTED',
        'providerMessage': 'Verification not available due to disconnection.',
    }
    assert unavailable_error.value.retryable is False


async def test_fetch_completion_signature_marks_not_found_as_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def not_found(_: str, __: Mapping[str, str]) -> FetchResponse:
        return FetchResponse(status=404, body=b'not found')

    use_fake_cloud_api_fetch(monkeypatch, not_found)

    with pytest.raises(ApiError) as not_found_error:
        await cloud_client().fetch_completion_signature('completion-id')

    assert not_found_error.value.failure.code == 'api.http_status'
    assert not_found_error.value.failure.details == {
        'resource': 'completion_signature',
        'status': 404,
    }
    assert not_found_error.value.retryable is True


@pytest.mark.parametrize(
    ('signing_algo', 'kind', 'signing_address'),
    [
        ('ecdsa', 'provider_tee', SIGNING_ADDRESS),
        ('ed25519', 'gateway', '55' * 32),
    ],
)
async def test_fetch_completion_signature_returns_found_signature(
    monkeypatch: pytest.MonkeyPatch,
    signing_algo: str,
    kind: str,
    signing_address: str,
) -> None:
    seen_url = ''

    async def found(url: str, headers: Mapping[str, str]) -> FetchResponse:
        nonlocal seen_url
        assert headers['authorization'] == 'Bearer test'
        seen_url = url
        return completion_signature_response(
            signing_algo=signing_algo,
            kind=kind,
            signing_address=signing_address,
        )

    use_fake_cloud_api_fetch(monkeypatch, found)

    signature = await cloud_client().fetch_completion_signature(
        'completion-id',
        signing_algo=signing_algo,
    )

    assert signature.kind == kind
    assert signature.signer == SigningIdentity(
        signing_algo=signing_algo,
        signing_address=signing_address,
    )
    assert urlsplit(seen_url).path == '/v1/signature/completion-id'
    assert parse_qs(urlsplit(seen_url).query) == {'signing_algo': [signing_algo]}


async def test_fetch_completion_signature_requires_signature_kind(
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
        await cloud_client().fetch_completion_signature('completion-id')
    assert malformed.value.failure.code == 'api.invalid_response'


@pytest.mark.parametrize(
    ('attestations', 'expected_code'),
    [
        (
            [
                verified_model_attestation_for_signer(
                    SigningIdentity(signing_algo='ecdsa', signing_address='44' * 20)
                )
            ],
            'api.model_attestation_signer_not_found',
        ),
        (
            [
                verified_model_attestation_for_signer(
                    SigningIdentity(
                        signing_algo='ecdsa', signing_address=SIGNING_ADDRESS
                    )
                ),
                verified_model_attestation_for_signer(
                    SigningIdentity(
                        signing_algo='ecdsa', signing_address=SIGNING_ADDRESS
                    )
                ),
            ],
            'api.ambiguous_model_attestation_signer',
        ),
    ],
)
def test_find_model_attestation_for_signature_requires_one_matching_signer(
    attestations: list[VerifiedModelAttestation],
    expected_code: str,
) -> None:
    signature = CompletionSignatureReference(
        kind='provider_tee',
        signer=SigningIdentity(signing_algo='ecdsa', signing_address=SIGNING_ADDRESS),
    )

    with pytest.raises(ApiError) as raised:
        find_model_attestation_for_signature(attestations, signature)

    assert raised.value.failure.code == expected_code


def test_find_model_attestation_for_signature_rejects_a_gateway_signature() -> None:
    signature = CompletionSignatureReference(
        kind='gateway',
        signer=SigningIdentity(signing_algo='ecdsa', signing_address=SIGNING_ADDRESS),
    )

    with pytest.raises(ApiError) as raised:
        find_model_attestation_for_signature(
            [verified_model_attestation_for_signer(signature.signer)],
            signature,
        )

    assert raised.value.failure.code == 'api.invalid_input'
    assert raised.value.failure.details == {
        'field': 'signature.kind',
        'reason': 'unsupported_value',
        'expected': 'provider_tee',
        'actual': 'gateway',
    }


async def test_model_attestation_fetch_rejects_invalid_signing_address_before_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = 0

    async def fake_fetch(*_: object, **__: object) -> FetchResponse:
        nonlocal requests
        requests += 1
        raise AssertionError('invalid helper input must not make a request')

    monkeypatch.setattr(cloud_api, 'default_fetch', fake_fetch)

    with pytest.raises(ApiError) as raised:
        await cloud_client().fetch_model_attestations(
            'canonical-model',
            signing_address='not-hex',
        )

    assert raised.value.failure.code == 'api.invalid_input'
    assert raised.value.failure.details == {
        'field': 'signing_address',
        'reason': 'invalid_hex',
    }
    assert requests == 0


@pytest.mark.parametrize(
    ('signing_address', 'details'),
    (
        pytest.param(
            'not-hex',
            {
                'field': 'signature.signer.signing_address',
                'reason': 'invalid_hex',
            },
            id='invalid-hex',
        ),
        pytest.param(
            '11' * 19,
            {
                'field': 'signature.signer.signing_address',
                'reason': 'wrong_length',
                'expected': '20-byte hexadecimal signing address',
                'actual': '19 bytes',
            },
            id='wrong-length',
        ),
    ),
)
def test_model_selection_rejects_malformed_manual_signer_input_as_api_error(
    signing_address: str,
    details: dict[str, str],
) -> None:
    signature = CompletionSignatureReference(
        kind='provider_tee',
        signer=SigningIdentity(signing_algo='ecdsa', signing_address=signing_address),
    )

    with pytest.raises(ApiError) as raised:
        find_model_attestation_for_signature([], signature)

    assert raised.value.failure.code == 'api.invalid_input'
    assert raised.value.failure.details == details


async def test_model_attestation_fetch_preserves_an_empty_collection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def no_attestations(_: str, __: Mapping[str, str]) -> FetchResponse:
        return FetchResponse(status=200, body=b'{}')

    use_fake_cloud_api_fetch(monkeypatch, no_attestations)

    fetched = await cloud_client().fetch_model_attestations('canonical-model')

    assert fetched.attestations == ()


async def test_model_attestation_fetch_preserves_multiple_records(
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

    fetched = await cloud_client().fetch_model_attestations('canonical-model')

    assert len(fetched.attestations) == 2
    assert all(
        attestation.nonce == fetched.client_binding.nonce
        for attestation in fetched.attestations
    )


async def test_model_attestation_fetch_checks_every_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def wrong_nonce(url: str, _: Mapping[str, str]) -> FetchResponse:
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'model_attestations': [
                        cloud_attestation(nonce),
                        cloud_attestation('44' * 32),
                    ]
                }
            ).encode(),
        )

    use_fake_cloud_api_fetch(monkeypatch, wrong_nonce)

    with pytest.raises(ApiError) as nonce_error:
        await cloud_client().fetch_model_attestations('canonical-model')
    assert nonce_error.value.failure.code == 'api.nonce_mismatch'


async def test_non_utf8_success_response_is_an_api_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def non_utf8(_: str, __: Mapping[str, str]) -> FetchResponse:
        return FetchResponse(status=200, body=b'\xff')

    use_fake_cloud_api_fetch(monkeypatch, non_utf8)

    with pytest.raises(ApiError) as raised:
        await cloud_client().fetch_model_attestations('canonical-model')

    assert raised.value.failure.code == 'api.invalid_json'
    assert raised.value.failure.details == {'resource': 'model_attestation'}
