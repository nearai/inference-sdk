import pytest

from test.common import (
    chat_completions,
    fetch_attestation_report,
    fetch_chat_signature,
    generate_request_nonce,
    sleep,
)
from test.context import init_context
from test.types import ChatCompletionsResponse, Context
from verification_sdk import (
    Chat,
    ChatSignature,
    ModelAttestation,
    SigningAlgo,
    verify_chat,
    verify_signing_address,
)


@pytest.mark.asyncio
class TestChat:
    @pytest.fixture(scope='class')
    def context(self) -> Context:
        return init_context()

    @pytest.fixture(scope='class')
    async def completions(self, context: Context) -> ChatCompletionsResponse:
        completions = await chat_completions(
            api_url=context['api_url'],
            api_key=context['api_key'],
            request_body={
                'model': context['model'],
                'messages': [
                    {
                        'role': 'user',
                        'content': 'Hello',
                    },
                ],
                'stream': True,
            },
        )

        await sleep(5 * 1000)  # Waiting for signature preparation
        return completions

    @pytest.mark.asyncio
    async def test_chat_signature_ecdsa(
        self, context: Context, completions: ChatCompletionsResponse
    ):
        await test_chat_signature(context, completions, 'ecdsa')

    @pytest.mark.asyncio
    async def test_chat_signature_ed25519(
        self, context: Context, completions: ChatCompletionsResponse
    ):
        await test_chat_signature(context, completions, 'ed25519')


async def test_chat_signature(
    context: Context,
    completions: ChatCompletionsResponse,
    signing_algo: SigningAlgo,
):
    signature = await fetch_chat_signature(
        api_url=context['api_url'],
        api_key=context['api_key'],
        chat_id=completions['id'],
        model=context['model'],
        signing_algo=signing_algo,
    )

    assert signature['signing_algo'] == signing_algo

    chat = Chat(
        request_body=completions['request_body_raw'],
        response_body=completions['response_body_raw'],
    )
    chat_signature = ChatSignature(**signature)

    verify_chat(chat, chat_signature)

    report = await fetch_attestation_report(
        api_url=context['api_url'],
        api_key=context['api_key'],
        model=context['model'],
        request_nonce=generate_request_nonce(),
        signing_algo=signing_algo,
    )

    model_attestations = [
        ModelAttestation(**att) for att in (report.get('model_attestations') or [])
    ]

    verify_signing_address(chat_signature, model_attestations)

