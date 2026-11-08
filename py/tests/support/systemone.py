"""Shared System One requests and signed server responses."""

import gzip
import hashlib
import json
from dataclasses import replace

import brotli
import httpx
from eth_account.messages import encode_defunct
from nacl.signing import SigningKey

from .gateway import MODEL, Gateway

IMAGE_PART = {
    'type': 'image_url',
    'image_url': {'url': 'data:image/png;base64,ZmFrZS1pbWFnZQ=='},
}
BOX_BOUNDS = {'top': 0.31, 'bottom': 0.69, 'left': 0.25, 'right': 0.75}
IMAGE_REQUEST = {
    'model': MODEL,
    'state': {'canvas': IMAGE_PART},
    'questions': {
        'region': {'type': 'box', 'instructions': ['Locate the rectangle', IMAGE_PART]},
        'present': {
            'type': 'noul',
            'instructions': 'Does the canvas match?',
            'criteria': {'true': IMAGE_PART},
        },
    },
}
REQUEST = {
    'model': MODEL,
    'state': {'question': 'Is this a useful answer?'},
    'questions': {
        'useful': {'type': 'noul', 'instructions': 'Is this a useful answer?'},
        'action': {
            'type': 'choice',
            'instructions': {'task': 'Decide whether to keep this answer.'},
            'criteria': {'keep': 'Use it', 'skip': None},
        },
        'quality': {
            'type': 'score',
            'instructions': ['Rate the answer.', {'context': 'Customer support'}],
            'criteria': ['low', 'high'],
        },
    },
}


class DecisionGateway(Gateway):
    def __init__(self, signing_algo='ed25519', kind='gateway'):
        super().__init__(signing_algo, kind)
        self.metadata = {
            'providerType': 'vllm' if kind == 'provider_tee' else 'typesafe',
            'attestationSupported': kind == 'provider_tee',
        }
        self.requests = []
        self.response_fault = None
        self.response_encoding = None
        self.decision_id = None
        self.body_id = None
        self.answers = None
        self.usage = None
        self.signature_urls = []
        self.omit_public_key = False
        self.use_alternate_signer = False
        self.alternate_key = SigningKey(bytes([9]) * 32)

    async def handle(self, request):
        if request.url.path != '/v1/systemone':
            if request.url.path.startswith('/v1/signature/'):
                self.signature_urls.append(request.url)
            response = await super().handle(request)
            if (
                request.url.path == '/v1/attestation/report'
                and 'model' in request.url.params
            ):
                body = response.json()
                # Reports may include other signing identities.
                for report in body['model_attestations']:
                    if self.omit_public_key:
                        report.pop('signing_public_key')
                if self.signing_algo == 'ed25519':
                    alternate = {**self.attestation(request.url.params['nonce'])}
                    quote = self.quotes[alternate['intel_quote']]
                    address = bytes(self.alternate_key.verify_key).hex()
                    self.quotes[alternate['intel_quote']] = replace(
                        quote,
                        report_data=bytes.fromhex(address) + quote.report_data[32:],
                    )
                    alternate.update(
                        signing_address=address,
                        report_data=self.quotes[
                            alternate['intel_quote']
                        ].report_data.hex(),
                    )
                    alternate.pop('signing_public_key')
                    body['model_attestations'].append(alternate)
                return httpx.Response(200, json=body)
            return response
        self.headers.append(request.headers)
        self.requests.append(request)
        decision_id = self.decision_id or f'systemone-{len(self.requests)}'
        if self.response_fault == 'status':
            return httpx.Response(
                503, text='private state must not be included in errors'
            )
        if json.loads(request.content)['questions'] == {}:
            return httpx.Response(422)
        body = {
            'model': MODEL,
            'answers': {
                'useful': {'type': 'noul', 'noul': 0.9},
                'action': {
                    'type': 'choice',
                    'choice': 'keep',
                    'confidence': 0.8,
                    'probabilities': {'keep': 0.8, 'skip': 0.2},
                },
                'quality': {
                    'type': 'score',
                    'score': 1,
                    'confidence': 0.9,
                    'probabilities': {'0': 0.1, '1': 0.9},
                    'legend': {'0': 'low', '1': 'high'},
                },
            },
            'usage': {'input_tokens': 5, 'output_tokens': 2},
        }
        if self.body_id is not None:
            body['id'] = self.body_id
        if self.answers is not None:
            body['answers'] = self.answers
        if self.usage is not None:
            body['usage'] = self.usage
        if self.response_fault == 'probability':
            body['answers']['useful']['noul'] = 2
        response_body = json.dumps(body).encode()
        if self.response_fault == 'json':
            response_body = b'not JSON'
        signed_text = (
            hashlib.sha256(request.content).hexdigest()
            + ':'
            + hashlib.sha256(response_body).hexdigest()
        )
        if self.kind == 'provider_tee':
            signed_text = MODEL + ':' + signed_text
        key = self.alternate_key if self.use_alternate_signer else self.key
        signature = (
            key.sign(signed_text.encode()).signature.hex()
            if self.signing_algo == 'ed25519'
            else key.sign_message(encode_defunct(text=signed_text)).signature.hex()
        )
        address = (
            bytes(key.verify_key).hex()
            if self.signing_algo == 'ed25519'
            else self.address
        )
        self.signatures[decision_id] = {
            'text': signed_text,
            'signature': signature,
            'signing_address': address,
            'signing_algo': self.signing_algo,
            'signature_kind': self.kind,
        }
        if self.response_fault == 'tamper':
            response_body = response_body.replace(b'0.9', b'0.5')
        if self.response_encoding == 'gzip':
            response_body = gzip.compress(response_body)
        elif self.response_encoding == 'br':
            response_body = brotli.compress(response_body)
        return httpx.Response(
            200,
            content=response_body,
            headers={
                **(
                    {'content-encoding': self.response_encoding}
                    if self.response_encoding
                    else {}
                ),
                'x-signature-id'
                if self.response_fault == 'id'
                else 'x-generation-id': decision_id,
            },
        )
