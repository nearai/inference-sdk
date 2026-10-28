"""Live hosted Jev decisions, verified through their Gateway receipts."""

import asyncio
import json
from urllib.parse import urljoin

import pytest
from typesafe_sdk import AsyncTypeSafeClient, Choice, Noul, RetryPolicy, Score

from e2e.helpers import required_env, retry_receipt, selected_models
from nearai_inference_sdk import (
    AttestationClient,
    InferenceClient,
    SigningAlgo,
    SystemOneRequest,
    VerificationError,
    create_pinned_tls_client,
    verify_gateway_attestation,
    verify_gateway_response,
)


def decision_request() -> SystemOneRequest:
    return {
        'model': selected_models('systemone', 'external')[0],
        'state': {'message': 'I was charged twice for my subscription. Please help.'},
        'questions': {
            'billing': {'type': 'noul', 'instructions': 'Is this about billing?'},
            'team': {
                'type': 'choice',
                'instructions': 'Which team should handle this?',
                'criteria': {
                    'billing': 'Payments and subscriptions',
                    'support': 'Technical issues',
                },
            },
            'urgency': {
                'type': 'score',
                'instructions': 'How urgent is this request?',
                'criteria': ['Routine', 'Needs prompt attention', 'Critical'],
            },
        },
    }


@pytest.mark.asyncio
@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
async def test_inference_client_verifies_jev_decisions(
    signing_algo: SigningAlgo,
) -> None:
    async with (
        asyncio.timeout(180),
        InferenceClient(
            required_env('NEARAI_API_KEY'),
            base_url=required_env('NEARAI_BASE_URL'),
            signing_algo=signing_algo,
            e2ee=False,
        ) as client,
    ):
        request = decision_request()
        # create() verifies Gateway evidence and pins TLS before inference.
        result = await client.systemone.create(request)
        assert result.decision_id, 'Expected the X-Generation-Id receipt index'
        verified = await retry_receipt(
            lambda: client.verify_response(result.decision_id)
        )
        assert verified.id == result.decision_id
        assert verified.signature_kind == 'gateway'
        assert verified.signature.signer.signing_algo == signing_algo
        assert verified.attestation.tls_binding.kind == 'attested'
        # The provider may return a dated revision instead of the catalog alias.
        assert result.data['model']
        answers = result.data['answers']
        assert answers['billing']['type'] == 'noul'
        assert answers['team']['type'] == 'choice'
        assert answers['urgency']['type'] == 'score'
        # Check the response contract, not a particular probabilistic decision.
        assert answers['team']['choice'] in request['questions']['team']['criteria']
        assert result.data['usage']['input_tokens'] > 0


@pytest.mark.asyncio
async def test_standalone_apis_bind_generation_id_to_exact_decision_bytes() -> None:
    async with asyncio.timeout(180):
        api_key = required_env('NEARAI_API_KEY')
        base_url = required_env('NEARAI_BASE_URL').rstrip('/') + '/'
        signing_algo = 'ed25519'
        client = AttestationClient(api_key, base_url=base_url)
        fetched_gateway = await client.fetch_gateway_attestation(
            signing_algo=signing_algo
        )
        gateway = await verify_gateway_attestation(
            fetched_gateway.attestation, fetched_gateway.client_binding
        )
        assert gateway.tls_binding.kind == 'attested'
        request_body = json.dumps(decision_request(), separators=(',', ':')).encode()
        async with create_pinned_tls_client(
            gateway.tls_binding.spki_fingerprint
        ) as pinned_tls_client:
            response = await pinned_tls_client.post(
                base_url + 'systemone',
                content=request_body,
                headers={
                    'Authorization': f'Bearer {api_key}',
                    'Content-Type': 'application/json',
                    'Accept-Encoding': 'identity',
                    'x-no-aliasing': 'true',
                },
            )
            assert response.status_code == 200, (
                f'System One returned HTTP {response.status_code}'
            )
            decision_id = response.headers.get('x-generation-id')
            assert decision_id, 'Expected X-Generation-Id even when the body has no id'
            response_body = response.content
        signature = await retry_receipt(
            lambda: client.fetch_completion_signature(
                decision_id, signing_algo=signing_algo
            )
        )
        assert signature.kind == 'gateway'
        verify_gateway_response(request_body, response_body, signature, gateway)
        # A real receipt rejects changed bytes on either side, without inference.
        with pytest.raises(VerificationError):
            verify_gateway_response(
                request_body + b' ', response_body, signature, gateway
            )
        with pytest.raises(VerificationError):
            verify_gateway_response(
                request_body, response_body + b' ', signature, gateway
            )


@pytest.mark.asyncio
@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
@pytest.mark.parametrize('kind', ['gateway', 'provider_tee'])
async def test_official_jev_sdk_verifies_live_receipt(kind, signing_algo):
    provider = 'near' if kind == 'provider_tee' else 'external'
    model = next(
        (
            entry['id']
            for entry in json.loads(required_env('NEARAI_E2E_MODELS'))
            if entry['endpoint'] == 'systemone' and entry['provider'] == provider
        ),
        None,
    )
    if kind == 'provider_tee' and model is None:
        pytest.skip('No self-hosted System One model selected; requires cloud-api#1285')
    assert model, 'Expected a selected System One model'

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

        adapter = inference.httpx2_client
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
                state=decision_request()['state'],
                questions={
                    'billing': Noul(instructions='Is this about billing?'),
                    'team': Choice(
                        instructions='Which team should handle this?',
                        criteria=decision_request()['questions']['team']['criteria'],
                    ),
                    'urgency': Score(
                        instructions='How urgent is this request?',
                        criteria=decision_request()['questions']['urgency']['criteria'],
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
        assert result.model
        assert result.usage.input_tokens is not None and result.usage.input_tokens > 0
        assert 0 <= result.nouls['billing'].noul <= 1
        assert result.choices['team'].choice in ('billing', 'support')
        assert result.scores['urgency'].score is not None
