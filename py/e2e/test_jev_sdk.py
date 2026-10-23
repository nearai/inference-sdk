"""Opt-in live official Jev SDK requests and NEAR receipt verification."""

import asyncio
import os
from urllib.parse import urljoin

import pytest
from typesafe_sdk import AsyncTypeSafeClient, Choice, Noul, RetryPolicy, Score

from e2e.helpers import required_env, retry_receipt, selected_models
from nearai_inference_sdk import InferenceClient


@pytest.mark.skipif(
    not (os.environ.get('NEARAI_API_KEY') and os.environ.get('NEARAI_BASE_URL')),
    reason='Set NEARAI_API_KEY and NEARAI_BASE_URL to run live Jev SDK tests',
)
@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
@pytest.mark.parametrize('kind', ['gateway', 'provider_tee'])
async def test_official_jev_sdk_verifies_live_receipt(kind, signing_algo):
    if kind == 'provider_tee':
        model = os.environ.get('NEARAI_JEV_SELF_HOSTED_MODEL')
        if not model:
            pytest.skip(
                'Self-hosted Jev requires cloud-api#1285 and '
                'NEARAI_JEV_SELF_HOSTED_MODEL'
            )
    else:
        model = (
            os.environ.get('NEARAI_JEV_MODEL')
            or selected_models('systemone', 'external')[0]
        )

    async with (
        asyncio.timeout(180),
        InferenceClient(
            required_env('NEARAI_API_KEY'),
            base_url=required_env('NEARAI_BASE_URL'),
            signing_algo=signing_algo,
            e2ee=False,
            ohttp=False,
        ) as inference,
    ):
        preflight = await inference.verify(model)
        selected = next(
            (
                report
                for report in preflight.models
                if report.signer.signing_algo == signing_algo
                and report.signing_public_key
            ),
            None,
        )
        if kind == 'provider_tee':
            assert selected is not None
        else:
            assert not preflight.models

        inference_requests = 0

        async def count_request(request):
            nonlocal inference_requests
            inference_requests += 1

        adapter = inference.http_client
        adapter.event_hooks['request'].append(count_request)
        async with AsyncTypeSafeClient(
            api_key=required_env('NEARAI_API_KEY'),
            base_url=urljoin(inference.base_url, '../'),
            http_client=adapter,
            compression=False,
            retry=RetryPolicy(max_retries=0),
            timeout=60,
        ) as jev:
            result = await jev.system_one(
                model=model,
                state={'message': 'I was charged twice. Please help.'},
                questions={
                    'billing': Noul(instructions='Is this about billing?'),
                    'team': Choice(
                        instructions='Choose a team.',
                        criteria={'billing': 'Payments', 'support': 'Other'},
                    ),
                    'urgency': Score(
                        instructions='Rate urgency.', criteria=['Routine', 'Urgent']
                    ),
                },
            )

        receipt_id = result.raw_http_response.headers['x-generation-id']
        assert receipt_id
        verified = await retry_receipt(lambda: inference.verify_response(receipt_id))
        assert verified.id == receipt_id
        assert verified.signature_kind == kind
        assert verified.signature.signer.signing_algo == signing_algo
        if kind == 'provider_tee':
            assert (
                verified.attestation.signer.signing_address
                == selected.signer.signing_address
            )
        assert inference_requests == 1
        assert 0 <= result.nouls['billing'].noul <= 1
        assert result.choices['team'].choice in ('billing', 'support')
        assert result.scores['urgency'].score is not None
