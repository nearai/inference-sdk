import asyncio
import json
import secrets
import aiohttp

from urllib.parse import quote
from verification_sdk import (
    AttestationReport,
    ChatSignature,
    DomainAttestation,
    SigningAlgo,
)

from .types import ChatCompletionsResponse


async def sleep(sec: int):
    await asyncio.sleep(sec)


def generate_request_nonce() -> str:
    return secrets.token_hex(32)


async def fetch_attestation_report(
    api_url: str,
    api_key: str,
    model: str,
    request_nonce: str,
    signing_algo: SigningAlgo,
) -> AttestationReport:
    url = f'{api_url}/attestation/report?model={quote(model)}&nonce={request_nonce}&signing_algo={signing_algo}'

    async with aiohttp.ClientSession() as session:
        async with session.get(
            url,
            headers={
                'authorization': f'Bearer {api_key}',
            },
        ) as response:
            if not response.ok:
                raise ValueError(
                    f'Failed to fetch attestation report with status code: {response.status}'
                )

            content = await response.read()
            return AttestationReport.model_validate_json(content)


async def fetch_chat_signature(
    api_url: str,
    api_key: str,
    chat_id: str,
    model: str,
    signing_algo: SigningAlgo,
) -> ChatSignature:
    url = f'{api_url}/signature/{chat_id}?model={quote(model)}&signing_algo={signing_algo}'

    async with aiohttp.ClientSession() as session:
        async with session.get(
            url,
            headers={
                'authorization': f'Bearer {api_key}',
            },
        ) as response:
            if not response.ok:
                raise ValueError(f'Failed to fetch signature with status code: {response.status}')

            content = await response.read()
            return ChatSignature.model_validate_json(content)


async def chat_completions(
    api_url: str,
    api_key: str,
    request_body: dict,
) -> ChatCompletionsResponse:
    request_body_raw = json.dumps(request_body).encode()

    async with aiohttp.ClientSession() as session:
        async with session.post(
            f'{api_url}/chat/completions',
            headers={
                'authorization': f'Bearer {api_key}',
                'content-type': 'application/json',
            },
            data=request_body_raw,
        ) as response:
            if not response.ok:
                raise ValueError(f'Failed to chat with status code: {response.status}')

            response_body_raw = await response.read()

            if request_body.get('stream'):
                lines = response_body_raw.decode().split('\n')
                first_chunk = json.loads(lines[0][6:])  # data: {...
                chat_id = first_chunk['id']
            else:
                data = json.loads(response_body_raw.decode())
                chat_id = data['id']

            return {
                'id': chat_id,
                'request_body_raw': request_body_raw,
                'response_body_raw': response_body_raw,
            }


async def fetch_domain_attestation(domain: str) -> DomainAttestation:
    evidences_url = f'https://{domain}/evidences/'

    intel_quote_url = f'{evidences_url}quote.json'
    cert_url = f'{evidences_url}cert-{domain}.pem'
    acme_account_url = f'{evidences_url}acme-account.json'
    sha256sum_url = f'{evidences_url}sha256sum.txt'
    info_url = f'{evidences_url}info.json'

    async def fetch_json(url: str) -> dict:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if not response.ok:
                    raise ValueError(
                        f'Failed to fetch {url} with status code: {response.status}'
                    )
                return await response.json()

    async def fetch_text(url: str) -> str:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if not response.ok:
                    raise ValueError(
                        f'Failed to fetch {url} with status code: {response.status}'
                    )
                return await response.text()

    intel_quote_data, cert_text, acme_account_text, sha256sum_text, info_data = await asyncio.gather(
        fetch_json(intel_quote_url),
        fetch_text(cert_url),
        fetch_text(acme_account_url),
        fetch_text(sha256sum_url),
        fetch_json(info_url),
    )

    return DomainAttestation.model_validate({
        'intel_quote': intel_quote_data['quote'],
        'domain': domain,
        'cert': cert_text,
        'acme_account': acme_account_text,
        'sha256sum': sha256sum_text,
        'info': info_data
    })

