"""Exercise the documented example without sending an inference request."""

import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from gateway import jev


class JevExampleTest(unittest.IsolatedAsyncioTestCase):
    async def test_receipt_kind_defaults_and_overrides(self):
        for configured_kind, returned_kind in (
            (None, 'gateway'),
            ('provider_tee', 'provider_tee'),
            (None, 'provider_tee'),
        ):
            with self.subTest(configured=configured_kind, returned=returned_kind):
                env = {
                    'NEARAI_API_KEY': 'test-key',
                    'NEARAI_BASE_URL': 'https://example.test/v1/',
                    'NEARAI_SYSTEMONE_MODEL': 'test-model',
                }
                if configured_kind is not None:
                    env['NEARAI_EXPECTED_SIGNATURE_KIND'] = configured_kind
                client = AsyncMock()
                client.__aenter__.return_value = client
                client.systemone.create.return_value = SimpleNamespace(
                    decision_id='decision-1', data={'answers': {}}
                )
                client.verify_response.return_value = SimpleNamespace(
                    signature_kind=returned_kind
                )
                with (
                    patch.dict(os.environ, env, clear=True),
                    patch.object(jev, 'InferenceClient', return_value=client),
                    patch('builtins.print') as output,
                ):
                    if configured_kind is None and returned_kind != 'gateway':
                        with self.assertRaisesRegex(
                            RuntimeError, 'Expected gateway, got provider_tee'
                        ):
                            await jev.main()
                        output.assert_not_called()
                    else:
                        await jev.main()
                        output.assert_any_call(f'Verified decision-1: {returned_kind}')
                    client.verify_response.assert_awaited_once_with('decision-1')

    async def test_all_questions_have_instructions_and_answers_are_verified(self):
        async def create(request):
            self.assertEqual(
                {question['type'] for question in request['questions'].values()},
                {'noul', 'choice', 'score'},
            )
            for question in request['questions'].values():
                self.assertIsInstance(question['instructions'], (str, dict, list))
                self.assertTrue(question['instructions'])
            return SimpleNamespace(decision_id='decision-1', data={'answers': {}})

        client = AsyncMock()
        client.__aenter__.return_value = client
        client.systemone.create.side_effect = create
        client.verify_response.return_value = SimpleNamespace(signature_kind='gateway')
        with (
            patch.dict(
                os.environ,
                {
                    'NEARAI_API_KEY': 'test-key',
                    'NEARAI_BASE_URL': 'https://example.test/v1/',
                    'NEARAI_SYSTEMONE_MODEL': 'test-model',
                    'NEARAI_EXPECTED_SIGNATURE_KIND': 'gateway',
                    'NEARAI_SIGNING_ALGO': 'ed25519',
                },
            ),
            patch.object(jev, 'InferenceClient', return_value=client),
            patch('builtins.print') as output,
        ):

            async def verify(decision_id):
                output.assert_not_called()
                return SimpleNamespace(signature_kind='gateway')

            client.verify_response.side_effect = verify
            await jev.main()
            client.systemone.create.assert_awaited_once()
            client.verify_response.assert_awaited_once_with('decision-1')
            output.assert_any_call('Verified decision-1: gateway')
