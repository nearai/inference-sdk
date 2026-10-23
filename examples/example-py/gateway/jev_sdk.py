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
    model = os.environ['NEARAI_SYSTEMONE_MODEL']
    async with verified_jev_clients(
        api_key,
        base_url=os.environ.get('NEARAI_BASE_URL', 'https://cloud-api.near.ai/v1/'),
    ) as (inference, jev):
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
                    criteria=['Routine', 'Needs attention', 'Critical'],
                ),
            },
        )
        verified = await inference.verify_response(receipt_id(result.raw_http_response))
        print(f'Verified {verified.signature_kind} receipt {verified.id}.')
        print(result.answers)


if __name__ == '__main__':
    asyncio.run(main())
