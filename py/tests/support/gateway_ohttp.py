"""OHTTP transport around the signed Gateway fixture."""

from __future__ import annotations

import httpx
from nacl.signing import SigningKey

from nearai_inference_sdk import InferenceClient

from .gateway import Gateway
from .ohttp import OhttpGateway


class _RecordedStream(httpx.AsyncByteStream):
    def __init__(self, stream: httpx.AsyncByteStream, chunks: list[bytes]):
        self.stream = stream
        self.chunks = chunks

    async def __aiter__(self):
        async for chunk in self.stream:
            self.chunks.append(chunk)
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class ObliviousGateway(Gateway):
    """Wrap the signed Gateway fixture with the real OHTTP server fixture."""

    def __init__(self, kind: str = 'provider_tee'):
        super().__init__(kind=kind)
        self.ohttp_gateway = OhttpGateway(handler=self.handle_inner)
        self.outer_requests: list[httpx.Request] = []
        self.transport_paths: list[str] = []
        self.response_chunks: list[list[bytes]] = []
        self.proof_failure: str | None = None

    async def handle_inner(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == '/v1/chat/completions'
        response = await super().handle(request)
        chunks: list[bytes] = []
        self.response_chunks.append(chunks)
        response.stream = _RecordedStream(response.stream, chunks)
        return response

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.transport_paths.append(request.url.path)
        if request.url.path == '/ohttp':
            self.outer_requests.append(request)
            return await self.ohttp_gateway.handle(request)
        response = await super().handle(request)
        if (
            request.url.path == '/v1/attestation/report'
            and 'model' not in request.url.params
        ):
            if self.proof_failure == 'missing':
                return response
            key = (
                SigningKey(bytes([9]) * 32)
                if self.proof_failure == 'signer'
                else self.key
            )
            config = (
                b'\x00'
                if self.proof_failure == 'malformed_config'
                else self.ohttp_gateway.key_config
            )
            payload = response.json()
            payload['ohttp_attestation'] = {
                'signing_algo': 'ed25519',
                'signing_key': bytes(key.verify_key).hex(),
                'key_config': config.hex(),
                'signature': (
                    '00' * 64
                    if self.proof_failure == 'signature'
                    else key.sign(config).signature.hex()
                ),
            }
            return httpx.Response(200, json=payload)
        return response

    def client(self, **options) -> InferenceClient:
        return super().client(ohttp=True, **options)
