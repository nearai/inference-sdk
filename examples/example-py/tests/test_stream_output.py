import contextlib
import gzip
import io
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from direct import chat_completions_bare as direct
from gateway import chat_completions_bare as gateway
from utils.chat_output import read_stream


class StreamOutputTests(unittest.IsolatedAsyncioTestCase):
    async def test_receipt_capture_uses_decoded_http_body(self):
        async def prepare(request, _key):
            async def decrypt(response):
                return response

            return SimpleNamespace(request=request, decrypt_response=decrypt)

        for streaming in (False, True):
            body = (
                b'data: {"id":"chat-fixture","choices":[{"delta":{"content":"ok"}}]}\n\n'
                b'data: [DONE]\n\ndata: ignored after [DONE]\n\n'
                if streaming
                else b'{"id":"chat-fixture","choices":[{"message":{"content":"ok"}}]}'
            )

            def respond(request, body=body, streaming=streaming):
                return httpx.Response(
                    200,
                    headers={
                        'content-encoding': 'gzip',
                        'content-type': 'text/event-stream'
                        if streaming
                        else 'application/json',
                    },
                    stream=httpx.ByteStream(gzip.compress(body)),
                )

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(respond)
            ) as client:
                with (
                    contextlib.redirect_stdout(io.StringIO()),
                    patch.object(direct, 'verify_direct_model_response') as verify,
                    patch.object(gateway, 'prepare_e2ee_chat_request', prepare),
                ):
                    await direct.send_and_verify(
                        client,
                        AsyncMock(),
                        SimpleNamespace(attestations=[]),
                        stream=streaming,
                    )
                    self.assertEqual(verify.call_args.args[1], body)

                    completion = await gateway.send_completion(
                        client, 'test', None, stream=streaming
                    )
                    self.assertEqual(completion.response_body, body)

    async def test_displays_before_done_and_handles_split_utf8(self):
        for separator in ('\n', '\r\n', '\r'):
            with self.subTest(separator=repr(separator)):
                await self.check_stream(separator)

    async def check_stream(self, separator):
        record = separator.join(
            [
                'data: {"id":"chat-fixture",',
                'data: "choices":[{"delta":{"content":"Hello 🌍"}}]}',
                '',
                '',
            ]
        ).encode()
        output = io.StringIO()
        test = self

        class Source(httpx.AsyncByteStream):
            async def __aiter__(self):
                # Disambiguate a trailing CR before checking incremental output.
                for byte in record + b':':
                    yield bytes([byte])
                test.assertEqual(output.getvalue(), 'Hello 🌍')
                yield (separator * 2 + 'data: [DONE]' + separator * 2).encode()
                yield b'data: \xff\n\n'

        with contextlib.redirect_stdout(output):
            response = httpx.Response(200, stream=Source())
            try:
                values = await read_stream(response)
            finally:
                await response.aclose()
        self.assertEqual(values[0]['id'], 'chat-fixture')
        self.assertEqual(output.getvalue(), 'Hello 🌍\n')

    async def test_removes_only_initial_bom_across_chunks(self):
        for prefix in (
            '\ufeff',
            '\ufeff\ufeffdata: {"error":"ignored"}\n\n',
            ': first\n\n\ufeffdata: {"error":"ignored"}\n\n',
        ):
            with self.subTest(prefix=repr(prefix)):
                await self.check_bom_stream(prefix)

    async def check_bom_stream(self, prefix):
        event = 'data: {"id":"chat-fixture","choices":[{"delta":{"content":"Hello 🌍"}}]}\n\n'
        record = (prefix + event).encode()
        output = io.StringIO()
        test = self

        class Source(httpx.AsyncByteStream):
            async def __aiter__(self):
                for byte in record:
                    yield bytes([byte])
                test.assertEqual(output.getvalue(), 'Hello 🌍')
                yield b'data: [DONE]\n\n'

        with contextlib.redirect_stdout(output):
            response = httpx.Response(200, stream=Source())
            try:
                values = await read_stream(response)
            finally:
                await response.aclose()
        self.assertEqual(values[0]['id'], 'chat-fixture')
        self.assertEqual(output.getvalue(), 'Hello 🌍\n')

    async def test_complete_event_at_eof(self):
        with contextlib.redirect_stdout(io.StringIO()):
            values = await read_stream(
                httpx.Response(200, content=b'data: {"id":"chat-1"}')
            )
        self.assertEqual(values, [{'id': 'chat-1'}])
        with self.assertRaises(UnicodeDecodeError):
            await read_stream(
                httpx.Response(200, content=b'data: {"id":"chat-1","extra":"\xff"}')
            )

    async def test_rejects_invalid_or_conflicting_completion_ids(self):
        for event in (b'{"id":"chat-other"}', b'{"id":""}', b'{"id":17}'):
            body = b'data: {"id":"chat-first"}\n\ndata: ' + event + b'\n\n'
            with (
                self.subTest(event=event),
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(RuntimeError, 'completion ID'),
            ):
                await read_stream(httpx.Response(200, content=body))

    async def test_rejects_error_events(self):
        for event in (b'{"error":"failed"}', b'{"type":"error","message":"failed"}'):
            with (
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(RuntimeError, 'Stream returned an error'),
            ):
                await read_stream(
                    httpx.Response(
                        200, content=b'data: ' + event + b'\n\ndata: [DONE]\n\n'
                    )
                )
