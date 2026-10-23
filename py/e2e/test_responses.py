"""Opt-in live Responses JSON/SSE and Gateway receipt verification."""

import asyncio

import pytest
from openai import AsyncOpenAI

from e2e.helpers import required_env, retry_receipt, selected_models
from nearai_inference_sdk import InferenceClient


@pytest.mark.asyncio
@pytest.mark.parametrize('ohttp', [False, True])
async def test_responses_json_and_sse(ohttp: bool) -> None:
    model = selected_models('chat', 'near')[0]
    api_key = required_env('NEARAI_API_KEY')
    base_url = required_env('NEARAI_BASE_URL')
    async with (
        asyncio.timeout(180),
        InferenceClient(api_key, base_url=base_url, e2ee=False, ohttp=ohttp) as client,
        AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=client.http_client,
            max_retries=0,
        ) as external,
    ):
        request = {
            'model': model,
            'input': 'Reply with the word OK.',
            'store': False,
            'max_output_tokens': 1024,
        }
        for stream in (False, True):
            if stream:
                events = await external.responses.create(**request, stream=True)
                response_id, completed = None, False
                async with events:
                    async for event in events:
                        if event.type == 'response.created':
                            response_id = event.response.id
                        if event.type == 'response.completed':
                            assert event.response.id == response_id
                            assert event.response.status == 'completed'
                            assert event.response.output
                            completed = True
                assert response_id and completed, (
                    'SSE must reach response.completed and EOF'
                )
            else:
                result = await client.responses.create(**request)
                assert result.status == 'completed'
                assert result.output
                response_id = result.id

            async with asyncio.timeout(15):
                receipt = await retry_receipt(
                    lambda response_id=response_id: client.verify_response(response_id)
                )
            assert receipt.id == response_id
            assert receipt.signature_kind == 'gateway'
