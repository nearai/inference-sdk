"""Use the official Jev SDK through NEAR's verified HTTPX2 transport."""

import asyncio
import os
from urllib.parse import urljoin

from nearai_inference_sdk import InferenceClient
from typesafe_sdk import AsyncTypeSafeClient, Choice, Noul, RetryPolicy, Score


async def main() -> None:
    api_key = os.environ['NEARAI_API_KEY']
    model = os.environ['NEARAI_SYSTEMONE_MODEL']
    async with InferenceClient(
        api_key,
        base_url=os.environ.get('NEARAI_BASE_URL', 'https://cloud-api.near.ai/v1/'),
        e2ee=False,
        ohttp=False,
    ) as inference:
        async with AsyncTypeSafeClient(
            api_key=api_key,
            # The official SDK appends /v1/systemone to its API root.
            base_url=urljoin(inference.base_url, '../'),
            http_client=inference.http_client,
            compression=False,
            retry=RetryPolicy(max_retries=0),
            timeout=60,
        ) as jev:
            result = await jev.system_one(
                model=model,
                state={
                    'message': 'I was charged twice for my subscription. Please help.'
                },
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
        # Closing Jev's borrowed adapter leaves the owner's receipts available.
        receipt_id = result.raw_http_response.headers['x-generation-id']
        verified = await inference.verify_response(receipt_id)
        print(f'Verified {verified.signature_kind} receipt {verified.id}.')
        print(result.answers)


if __name__ == '__main__':
    asyncio.run(main())
