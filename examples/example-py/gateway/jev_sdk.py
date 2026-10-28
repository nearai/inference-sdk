"""Use the official Jev SDK through NEAR's verified Jev adapter."""

import asyncio
import os

from typesafe_sdk import Choice, Noul, Score

if __package__:
    from .jev_helpers import receipt_id, verified_jev_clients
else:
    from jev_helpers import receipt_id, verified_jev_clients


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    model = os.environ['NEARAI_MODEL']
    signing_algo = os.environ.get('NEARAI_SIGNING_ALGO', 'ed25519')
    expected_kind = os.environ.get('NEARAI_EXPECT_SIGNATURE_KIND', 'gateway')
    if signing_algo not in ('ed25519', 'ecdsa') or expected_kind not in (
        'gateway',
        'provider_tee',
    ):
        raise ValueError('Invalid signing algorithm or signature kind')
    async with (
        asyncio.timeout(120),
        verified_jev_clients(
            api_key,
            base_url=os.environ.get('NEARAI_BASE_URL', 'https://cloud-api.near.ai/v1/'),
            signing_algo=signing_algo,
            expected_kind=expected_kind,
        ) as (inference, jev),
    ):
        result = await jev.system_one(
            model=model,
            state={'message': 'I was charged twice for my subscription. Please help.'},
            questions={
                'billing': Noul(instructions='Is this about billing?'),
                'team': Choice(
                    instructions='Which team should handle this?',
                    criteria={
                        'billing': 'Payments and subscriptions',
                        'support': 'Technical issues',
                    },
                ),
                'urgency': Score(
                    instructions='How urgent is this request?',
                    criteria=['Routine', 'Needs prompt attention', 'Critical'],
                ),
            },
        )
        verified = await inference.verify_response(receipt_id(result.raw_http_response))
        if verified.signature_kind != expected_kind:
            raise RuntimeError(
                f'Expected {expected_kind}, got {verified.signature_kind}'
            )
        print(f'Verified {verified.signature_kind} receipt {verified.id}.')
        print(result.model_dump_json(include={'answers', 'usage'}, indent=2))


if __name__ == '__main__':
    asyncio.run(main())
