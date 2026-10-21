"""Live hosted Jev decisions, verified through their Gateway receipts."""

import asyncio
import json

import pytest

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
