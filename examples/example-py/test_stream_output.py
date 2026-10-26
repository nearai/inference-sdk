import contextlib
import io
import unittest

import httpx

from direct.bare import read_stream as read_direct
from gateway.bare import read_stream as read_gateway


class StreamOutputTests(unittest.IsolatedAsyncioTestCase):
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

    async def test_truncated_stream_is_an_error(self):
        for read_stream in (read_direct, read_gateway):
            with (
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(RuntimeError, 'without'),
            ):
                await read_stream(httpx.Response(200, content=b'data: {}\n\n'))
