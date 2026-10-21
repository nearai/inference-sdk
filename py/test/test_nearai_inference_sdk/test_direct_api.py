import json
from urllib.parse import parse_qs, urlsplit

import pytest

from nearai_inference_sdk import ApiError, DirectAttestationClient
from nearai_inference_sdk.core import cloud_api
from nearai_inference_sdk.utils.fetch import FetchResponse

from .test_cloud_api import cloud_attestation


@pytest.mark.parametrize(
    'fault', [None, 'missing_serving', 'nonce', 'fingerprint', 'empty']
)
async def test_direct_fetch_validates_every_report_and_requires_serving_evidence(
    monkeypatch, fault
):
    async def fetch(url, **kwargs):
        query = parse_qs(urlsplit(url).query)
        assert 'model' not in query and 'provider' not in query
        assert query['include_tls_fingerprint'] == ['false']
        assert query['signing_algo'] == ['ecdsa']
        root = cloud_attestation(
            query['nonce'][0], model_name='test-model', tls_cert_fingerprint=None
        )
        sibling = {**root, 'intel_quote': 'bb'}
        if fault == 'nonce':
            sibling['request_nonce'] = '77' * 32
        if fault == 'fingerprint':
            sibling['tls_cert_fingerprint'] = '33' * 32
        reports = [root, sibling]
        if fault == 'missing_serving':
            reports = [sibling]
        if fault == 'empty':
            reports = []
        return FetchResponse(
            status=200, body=json.dumps({**root, 'all_attestations': reports}).encode()
        )

    monkeypatch.setattr(cloud_api, 'default_fetch', fetch)
    client = DirectAttestationClient('https://model.test/v1')
    if fault is None:
        fetched = await client.fetch_model_attestations(signing_algo='ecdsa')
        assert len(fetched.attestations) == 2
        assert fetched.serving_attestation == fetched.attestations[0]
        assert all(
            item.nonce == fetched.client_binding.nonce for item in fetched.attestations
        )
    else:
        with pytest.raises(ApiError) as raised:
            await client.fetch_model_attestations(signing_algo='ecdsa')
        assert raised.value.failure.code == (
            'api.nonce_mismatch' if fault == 'nonce' else 'api.invalid_response'
        )


async def test_direct_signature_does_not_require_gateway_kind_field(monkeypatch):
    async def fetch(url, **kwargs):
        assert '/signature/chat-id?' in url
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    'text': 'request:response',
                    'signature': 'aa',
                    'signing_algo': 'ed25519',
                    'signing_address': '22' * 32,
                }
            ).encode(),
        )

    monkeypatch.setattr(cloud_api, 'default_fetch', fetch)
    signature = await DirectAttestationClient(
        'https://model.test/v1'
    ).fetch_completion_signature('chat-id', signing_algo='ed25519')
    assert signature.kind == 'provider_tee'
