"""Signed in-process Gateway and Chat response fixtures."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from eth_account import Account
from eth_account.messages import encode_defunct
from nacl.signing import SigningKey

from nearai_inference_sdk import (
    AttestationVerifiers,
    E2eeModelKey,
    GatewayVerificationOptions,
    InferenceClient,
    ModelAttestationVerifiers,
    ModelVerificationOptions,
)
from nearai_inference_sdk.core import cloud_api
from nearai_inference_sdk.core.e2ee import (
    EcdsaE2eeClientKeyPair,
    Ed25519E2eeClientKeyPair,
    build_e2ee_request_aad,
    decrypt_e2ee_text,
    e2ee_field_aad,
    encrypt_e2ee_text,
)
from nearai_inference_sdk.utils.fetch import FetchResponse

from .attestation import APP_COMPOSE, TLS_FINGERPRINT, create_model_quote

BASE_URL = 'https://gateway.test/v1/'
MODEL = 'test-model'
MESSAGES = [{'role': 'user', 'content': 'Hello'}]


class ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], tail_gate: asyncio.Event | None = None):
        self.chunks = chunks
        self.tail_gate = tail_gate

    async def __aiter__(self):
        for index, chunk in enumerate(self.chunks):
            if self.tail_gate is not None and index == len(self.chunks) - 1:
                await self.tail_gate.wait()
            yield chunk


class Gateway:
    """Real message crypto; only the hardware quote verifier is substituted."""

    def __init__(
        self,
        signing_algo: str = 'ed25519',
        kind: str = 'provider_tee',
        *,
        seed: bytes = bytes([7]) * 32,
    ):
        self.signing_algo = signing_algo
        self.kind = kind
        self.gateway_requests = 0
        self.model_requests: list[str] = []
        self.completion_requests: list[httpx.Request] = []
        self.signature_requests = 0
        self.plaintexts: list[str] = []
        self.headers: list[httpx.Headers] = []
        self.attestation_headers: list[httpx.Headers] = []
        self.pins: list[str | None] = []
        self.peer_spki_fingerprint: str | None = TLS_FINGERPRINT
        self.quotes = {}
        self.signatures = {}
        self.metadata = {'providerType': 'vllm', 'attestationSupported': True}
        self.model_report_count = 1
        self.additional_model_is_invalid = False
        self.bad_quote = False
        self.tail_gate: asyncio.Event | None = None
        self.chat_body: bytes | None = None
        self.seed = seed
        if signing_algo == 'ed25519':
            self.key = SigningKey(self.seed)
            self.public_key = bytes(self.key.verify_key).hex()
            self.address = self.public_key
            self.encryption_key = Ed25519E2eeClientKeyPair(
                public_key=self.public_key,
                x25519_secret_key=bytes(self.key.to_curve25519_private_key()),
            )
        else:
            private_key = ec.derive_private_key(
                int.from_bytes(self.seed), ec.SECP256K1()
            )
            self.key = Account.from_key(self.seed)
            self.public_key = (
                private_key.public_key()
                .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]
                .hex()
            )
            self.address = self.key.address
            self.encryption_key = EcdsaE2eeClientKeyPair(
                public_key=self.public_key, private_key=private_key
            )

    def attestation(self, nonce: str):
        quote_id = f'{len(self.quotes) + 1:02x}'
        quote = create_model_quote(signing_address=self.address)
        quote = replace(
            quote,
            report_data=quote.report_data[:32] + bytes.fromhex(nonce),
            debug_enabled=self.bad_quote,
        )
        self.quotes[quote_id] = quote
        return {
            'request_nonce': nonce,
            'signing_algo': self.signing_algo,
            'signing_address': self.address,
            'signing_public_key': self.public_key,
            'intel_quote': quote_id,
            'report_data': quote.report_data.hex(),
            'event_log': [
                {
                    'digest': '00' * 48,
                    'imr': 3,
                    'event_type': 0,
                    'event': 'compose-hash',
                    'event_payload': 'beef',
                }
            ],
            'info': {'tcb_info': {'app_compose': APP_COMPOSE}},
        }

    async def handle(self, request: httpx.Request) -> httpx.Response:
        if (
            request.url.path == '/v1/attestation/report'
            and 'model' not in request.url.params
        ):
            self.attestation_headers.append(request.headers)
            assert all(
                name not in request.headers
                for name in ('authorization', 'api-key', 'x-api-key')
            )
        else:
            self.headers.append(request.headers)
        if request.url.path.startswith('/v1/model/'):
            return httpx.Response(200, json={'metadata': self.metadata})
        if request.url.path == '/v1/attestation/report':
            await asyncio.sleep(
                0
            )  # Concurrent callers share the same pending preflight.
            nonce = request.url.params['nonce']
            if 'model' in request.url.params:
                self.model_requests.append(request.url.params['model'])
                attestations = [
                    self.attestation(nonce) for _ in range(self.model_report_count)
                ]
                if self.additional_model_is_invalid:
                    self.bad_quote = True
                    attestations.append(self.attestation(nonce))
                return httpx.Response(200, json={'model_attestations': attestations})
            self.gateway_requests += 1
            report = self.attestation(nonce)
            if request.url.params['include_tls_fingerprint'] == 'true':
                signer = bytes.fromhex(self.address.removeprefix('0x'))
                prefix = hashlib.sha256(
                    signer + bytes.fromhex(TLS_FINGERPRINT)
                ).digest()
                quote = replace(
                    self.quotes[report['intel_quote']],
                    report_data=prefix + bytes.fromhex(nonce),
                )
                self.quotes[report['intel_quote']] = quote
                report['report_data'] = quote.report_data.hex()
                report['tls_cert_fingerprint'] = TLS_FINGERPRINT
            return httpx.Response(200, json={'gateway_attestation': report})

        if request.url.path.startswith('/v1/signature/'):
            self.signature_requests += 1
            return httpx.Response(
                200,
                json=self.signatures[request.url.path.removeprefix('/v1/signature/')],
            )

        assert request.url.path == '/v1/chat/completions'
        self.completion_requests.append(request)
        body = json.loads(request.content)
        client_key = request.headers.get('x-client-pub-key')
        content = body['messages'][0]['content']
        if client_key:
            aad = e2ee_field_aad(
                build_e2ee_request_aad(
                    E2eeModelKey(signing_algo=self.signing_algo, public_key=client_key)
                ),
                'messages[].content',
            )
            content = decrypt_e2ee_text(content, self.encryption_key, 'content', aad)
        self.plaintexts.append(content)
        response_content = 'Hello back'
        if client_key:
            response_content = encrypt_e2ee_text(
                response_content,
                E2eeModelKey(signing_algo=self.signing_algo, public_key=client_key),
            )
        completion_id = f'chatcmpl-{len(self.completion_requests)}'
        completion = {
            'id': completion_id,
            'created': 0,
            'model': body['model'],
            'object': 'chat.completion',
            'choices': [
                {
                    'index': 0,
                    'message': {'role': 'assistant', 'content': response_content},
                    'finish_reason': 'stop',
                }
            ],
        }
        if body.get('stream'):
            completion['object'] = 'chat.completion.chunk'
            completion['choices'] = [
                {
                    'index': 0,
                    'delta': {'content': response_content},
                    'finish_reason': 'stop',
                }
            ]
            # A multiline CRLF event exercises both decryption and receipt capture.
            text = json.dumps(completion)
            first, rest = text.split(',', 1)
            response_bytes = f'data: {first},\r\ndata: {rest}\r\n\r\n'.encode()
            response_bytes += b'data: [DONE]\r\n\r\n'
            if self.tail_gate is not None:
                response_bytes += b': signed trailing bytes\r\n\r\n'
            content_type = 'text/event-stream'
        else:
            response_bytes = json.dumps(completion).encode()
            content_type = 'application/json'
        if self.chat_body is not None:
            completion_id, response_bytes = 'chat-1', self.chat_body

        signed_text = ':'.join(
            (
                hashlib.sha256(request.content).hexdigest(),
                hashlib.sha256(response_bytes).hexdigest(),
            )
        )
        if self.kind == 'provider_tee':
            signed_text = f'{body["model"]}:{signed_text}'
        signature = (
            self.key.sign(signed_text.encode()).signature.hex()
            if self.signing_algo == 'ed25519'
            else self.key.sign_message(encode_defunct(text=signed_text)).signature.hex()
        )
        self.signatures[completion_id] = {
            'text': signed_text,
            'signature': signature,
            'signing_algo': self.signing_algo,
            'signing_address': self.address,
            'signature_kind': self.kind,
        }
        chunks = (
            [response_bytes]
            if self.chat_body is not None
            else response_bytes.split(b'data: [DONE]')
        )
        if len(chunks) == 2:
            chunks[1] = b'data: [DONE]' + chunks[1]
        if self.tail_gate is not None:
            done, tail = chunks[-1].split(b': signed trailing bytes')
            chunks[-1] = done
            chunks.append(b': signed trailing bytes' + tail)
        return httpx.Response(
            200,
            stream=ChunkStream(chunks, self.tail_gate),
            headers={'content-type': content_type},
        )

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fetch(url, *, headers=None, **kwargs):
            response = await self.handle(httpx.Request('GET', url, headers=headers))
            return FetchResponse(
                status=response.status_code,
                body=response.content,
                peer_spki_fingerprint=self.peer_spki_fingerprint,
            )

        monkeypatch.setattr(cloud_api, 'default_fetch', fetch)

        def create_client(_client, fingerprint):
            self.pins.append(fingerprint)
            return httpx.AsyncClient(transport=httpx.MockTransport(self.handle))

        monkeypatch.setattr(InferenceClient, '_create_gateway_client', create_client)

    def client(self, api_key: str | None = 'test-key', **options) -> InferenceClient:
        options.setdefault('e2ee', True)
        options.setdefault('signing_algo', self.signing_algo)
        options.setdefault(
            'model_verification',
            ModelVerificationOptions(
                verifiers=ModelAttestationVerifiers(tdx_quote=self.quotes.__getitem__),
            ),
        )
        options.setdefault(
            'gateway_verification',
            GatewayVerificationOptions(
                include_spki_fingerprint=False,
                verifiers=AttestationVerifiers(tdx_quote=self.quotes.__getitem__),
            ),
        )
        return InferenceClient(
            api_key,
            base_url=BASE_URL,
            **options,
        )
