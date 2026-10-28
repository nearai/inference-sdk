"""System One decisions: verify captured bytes before using the answers."""

import asyncio
import json
import os
from base64 import b64encode
from pathlib import Path

from nearai_inference_sdk import (
    InferenceClient,
    ModelAttestationPolicy,
    ModelVerificationOptions,
    SystemOneRequest,
)


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    base_url = os.environ.get('NEARAI_BASE_URL', 'https://cloud-api.near.ai/v1/')
    model = os.environ['NEARAI_MODEL']
    expected_kind = os.environ.get('NEARAI_EXPECT_SIGNATURE_KIND', 'gateway')
    signing_algo = os.environ.get('NEARAI_SIGNING_ALGO', 'ed25519')
    if signing_algo not in ('ed25519', 'ecdsa'):
        raise ValueError('NEARAI_SIGNING_ALGO must be ed25519 or ecdsa')
    if expected_kind not in ('provider_tee', 'gateway'):
        raise ValueError('NEARAI_EXPECT_SIGNATURE_KIND must be provider_tee or gateway')
    request: SystemOneRequest = {
        'model': model,
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
    if image_path := os.environ.get('NEARAI_IMAGE_PATH'):
        image_base64 = b64encode(Path(image_path).read_bytes()).decode('ascii')
        request = {
            'model': model,
            'state': {
                'photo': {
                    'type': 'image_url',
                    'image_url': {'url': f'data:image/png;base64,{image_base64}'},
                },
            },
            'questions': {
                'region': {'type': 'box', 'instructions': 'the main object in `photo`'},
            },
        }
    # System One supports neither field E2EE nor OHTTP. Both default to False.
    async with (
        asyncio.timeout(120),
        InferenceClient(
            api_key,
            base_url=base_url,
            signing_algo=signing_algo,
            model_verification=ModelVerificationOptions(policy=ModelAttestationPolicy())
            if expected_kind == 'provider_tee'
            else None,
        ) as client,
    ):
        result = await client.systemone.create(request)
        verified = await client.verify_response(result.decision_id)
        if verified.signature_kind != expected_kind:
            raise RuntimeError(
                f'Expected {expected_kind}, got {verified.signature_kind}'
            )
        print(f'Verified {verified.signature_kind} receipt {result.decision_id}.')
        print(
            json.dumps(
                {'answers': result.data['answers'], 'usage': result.data['usage']},
                ensure_ascii=False,
                indent=2,
            )
        )


if __name__ == '__main__':
    asyncio.run(main())
