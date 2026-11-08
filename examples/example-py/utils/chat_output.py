"""Display Chat streams and retain the exact decoded HTTP response bytes."""

import json
from collections.abc import AsyncIterator

import httpx


class RecordingStream(httpx.AsyncByteStream):
    """Keep the decoded HTTP body before decryption or display parsing."""

    def __init__(self, response: httpx.Response) -> None:
        self.response = response
        self.chunks: list[bytes] = []

    async def __aiter__(self):
        async for chunk in self.response.aiter_bytes():
            self.chunks.append(chunk)
            yield chunk

    async def aclose(self) -> None:
        await self.response.aclose()


async def _lines(chunks: AsyncIterator[bytes]) -> AsyncIterator[str]:
    pending = bytearray()
    after_cr = False
    async for chunk in chunks:
        if not chunk:
            continue
        if after_cr:
            chunk = chunk.removeprefix(b'\n')
        after_cr = chunk.endswith(b'\r')
        for part in chunk.splitlines(keepends=True):
            pending.extend(part)
            if part.endswith((b'\r', b'\n')):
                yield pending.rstrip(b'\r\n').decode()
                pending.clear()
    if pending:
        yield pending.decode()


async def _events(chunks: AsyncIterator[bytes]):
    event, data = '', []
    first = True
    async for line in _lines(chunks):
        if first:
            line = line.removeprefix('\ufeff')
            first = False
        if line == 'data':
            data.append('')
        elif line.startswith('data:'):
            data.append(line[5:].removeprefix(' '))
        elif line == 'event':
            event = ''
        elif line.startswith('event:'):
            event = line[6:].removeprefix(' ')
        elif not line:
            yield event, '\n'.join(data)
            event, data = '', []
    if event or data:
        yield event, '\n'.join(data)


async def read_stream(response: httpx.Response) -> list[dict]:
    values = []
    completion_id = None
    chunks = response.aiter_bytes()
    async for event, payload in _events(chunks):
        if event == 'error':
            raise RuntimeError('Stream returned an error')
        if payload == '[DONE]':
            # Drain the signed body without parsing bytes after [DONE].
            async for _ in chunks:
                pass
            break
        elif payload:
            value = json.loads(payload)
            if 'error' in value or value.get('type') == 'error':
                raise RuntimeError('Stream returned an error')
            if 'id' in value:
                candidate = value['id']
                if not isinstance(candidate, str) or not candidate:
                    raise RuntimeError('Stream returned an invalid completion ID')
                if completion_id is not None and candidate != completion_id:
                    raise RuntimeError('Stream returned conflicting completion IDs')
                completion_id = candidate
            values.append(value)
            for choice in value.get('choices', [])[:1]:
                print(choice.get('delta', {}).get('content') or '', end='', flush=True)
    print()
    return values
