"""Display Chat streams and retain the exact decoded HTTP response bytes."""

import json

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


async def read_stream(response: httpx.Response) -> list[dict]:
    values, data = [], []
    completion_id = None
    done = False
    first_line = True
    async for line in response.aiter_lines():
        if done:
            continue
        if first_line:
            line = line.removeprefix('\ufeff')
            first_line = False
        if line == 'data':
            data.append('')
        elif line.startswith('data:'):
            data.append(line[5:].removeprefix(' '))
        elif not line:
            payload = '\n'.join(data)
            data = []
            if payload == '[DONE]':
                done = True
            elif payload:
                value = json.loads(payload)
                if value.get('error') or value.get('type') == 'error':
                    raise RuntimeError('Stream returned an error')
                if value.get('id'):
                    if completion_id is not None and value['id'] != completion_id:
                        raise RuntimeError('Stream returned conflicting completion IDs')
                    completion_id = value['id']
                values.append(value)
                for choice in value.get('choices', [])[:1]:
                    print(
                        choice.get('delta', {}).get('content') or '', end='', flush=True
                    )
    print()
    if not done:
        raise RuntimeError('Stream ended without [DONE]')
    return values
