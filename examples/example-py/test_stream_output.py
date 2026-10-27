import contextlib
import gzip
import io
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from direct import bare as direct
from direct.bare import read_stream as read_direct
from gateway import bare as gateway
from gateway.bare import read_stream as read_gateway


class StreamOutputTests(unittest.IsolatedAsyncioTestCase):
    async def test_receipt_capture_uses_decoded_http_body(self):
        async def prepare(request, _key):
            async def decrypt(response):
                return response

            return SimpleNamespace(request=request, decrypt_response=decrypt)

        for streaming in (False, True):
            body = (
                b'data: {"id":"chat-fixture","choices":[{"delta":{"content":"ok"}}]}\n\n'
                b'data: [DONE]\n\n'
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
                        client, 'test', SimpleNamespace(key=None), stream=streaming
                    )
                    self.assertEqual(completion.response_body, body)

    async def test_displays_before_done_and_handles_split_utf8(self):
        for read_stream in (read_direct, read_gateway):
            for separator in ('\n', '\r\n', '\r'):
                await self.check_stream(read_stream, separator)

    async def check_stream(self, read_stream, separator):
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

        with contextlib.redirect_stdout(output):
            response = httpx.Response(200, stream=Source())
            try:
                values = await read_stream(response)
            finally:
                await response.aclose()
        self.assertEqual(values[0]['id'], 'chat-fixture')
        self.assertEqual(output.getvalue(), 'Hello 🌍\n')

    async def test_removes_only_initial_bom_across_chunks(self):
        for read_stream in (read_direct, read_gateway):
            for prefix in (
                '\ufeff',
                '\ufeff\ufeffdata: {"error":"ignored"}\n\n',
                ': first\n\n\ufeffdata: {"error":"ignored"}\n\n',
            ):
                await self.check_bom_stream(read_stream, prefix)

    async def check_bom_stream(self, read_stream, prefix):
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

    async def test_truncated_stream_is_an_error(self):
        for read_stream in (read_direct, read_gateway):
            with (
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(RuntimeError, 'without'),
            ):
                await read_stream(httpx.Response(200, content=b'data: {}\n\n'))
