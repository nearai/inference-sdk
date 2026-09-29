"""System One decisions: verify captured bytes before using the answers."""

import asyncio
import os

from nearai_inference_sdk import InferenceClient


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    base_url = os.environ['NEARAI_BASE_URL']
    model = os.environ['NEARAI_SYSTEMONE_MODEL']
    expected_kind = os.environ['NEARAI_EXPECTED_SIGNATURE_KIND']
    signing_algo = os.environ.get('NEARAI_SIGNING_ALGO', 'ed25519')
    if signing_algo not in ('ed25519', 'ecdsa'):
        raise ValueError('NEARAI_SIGNING_ALGO must be ed25519 or ecdsa')
    if expected_kind not in ('provider_tee', 'gateway'):
        raise ValueError(
            'NEARAI_EXPECTED_SIGNATURE_KIND must be provider_tee or gateway'
        )
    # System One supports neither field E2EE nor OHTTP. Both default to False.
    async with InferenceClient(
        api_key, base_url=base_url, signing_algo=signing_algo
    ) as client:
        result = await client.systemone.create(
            {
                'model': model,
                'state': {'message': 'The user wants a concise explanation.'},
                'questions': {
                    'brief': {
                        'type': 'noul',
                        'instructions': 'Should the answer be brief?',
                    },
                    'format': {
                        'type': 'choice',
                        'criteria': {'text': 'Use plain text', 'code': 'Use code'},
                    },
                    'detail': {
                        'type': 'score',
                        'criteria': ['brief', 'moderate', 'detailed'],
                    },
                },
            }
        )
        verified = await client.verify_response(result.decision_id)
        if verified.signature_kind != expected_kind:
            raise RuntimeError(
                f'Expected {expected_kind}, got {verified.signature_kind}'
            )
        print(result.data['answers'])
        print(f'Verified {result.decision_id}: {verified.signature_kind}')


if __name__ == '__main__':
    asyncio.run(main())
