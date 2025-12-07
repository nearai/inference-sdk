import asyncio
import json
import secrets
import requests

from verification_sdk import (
    AttestationReport,
    ChatSignature,
    DomainAttestation,
    SigningAlgo,
)
from .types import ChatCompletionsResponse


async def sleep(ms: int):
    await asyncio.sleep(ms / 1000)


def generate_request_nonce() -> str:
    return secrets.token_hex(32)


async def fetch_attestation_report(
    api_url: str,
    api_key: str,
    model: str,
    request_nonce: str,
    signing_algo: SigningAlgo,
) -> AttestationReport:
    url = f'{api_url}/attestation/report?model={requests.utils.quote(model)}&nonce={request_nonce}&signing_algo={signing_algo}'

    response = await asyncio.to_thread(
        requests.get,
        url,
        headers={
            'authorization': f'Bearer {api_key}',
        },
    )

    if not response.ok:
        raise ValueError(
            f'Failed to fetch attestation report with status code: {response.status_code}'
        )

    return AttestationReport.model_validate_json(response.content)


async def fetch_chat_signature(
    api_url: str,
    api_key: str,
    chat_id: str,
    model: str,
    signing_algo: SigningAlgo,
) -> ChatSignature:
    url = f'{api_url}/signature/{chat_id}?model={requests.utils.quote(model)}&signing_algo={signing_algo}'

    response = await asyncio.to_thread(
        requests.get,
        url,
        headers={
            'authorization': f'Bearer {api_key}',
        },
    )

    if not response.ok:
        raise ValueError(f'Failed to fetch signature with status code: {response.status_code}')

    return ChatSignature.model_validate_json(response.content)


async def chat_completions(
    api_url: str,
    api_key: str,
    request_body: dict,
) -> ChatCompletionsResponse:
    request_body_raw = json.dumps(request_body).encode()

    response = await asyncio.to_thread(
        requests.post,
        f'{api_url}/chat/completions',
        headers={
            'authorization': f'Bearer {api_key}',
            'content-type': 'application/json',
        },
        data=request_body_raw,
    )

    if not response.ok:
        raise ValueError(f'Failed to chat with status code: {response.status_code}')

    response_body_raw = response.content

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

    responses = await asyncio.gather(
        asyncio.to_thread(requests.get, intel_quote_url),
        asyncio.to_thread(requests.get, cert_url),
        asyncio.to_thread(requests.get, acme_account_url),
        asyncio.to_thread(requests.get, sha256sum_url),
        asyncio.to_thread(requests.get, info_url),
    )

    intel_quote_res, cert_res, acme_account_res, sha256sum_res, info_res = responses

    if not intel_quote_res.ok:
        raise ValueError(
            f'Failed to fetch intel quote with status code: {intel_quote_res.status_code}'
        )

    if not cert_res.ok:
        raise ValueError(
            f'Failed to fetch certificate with status code: {cert_res.status_code}'
        )

    if not acme_account_res.ok:
        raise ValueError(
            f'Failed to fetch ACME account with status code: {acme_account_res.status_code}'
        )

    if not sha256sum_res.ok:
        raise ValueError(
            f'Failed to fetch sha256 sum with status code: {sha256sum_res.status_code}'
        )

    if not info_res.ok:
        raise ValueError(f'Failed to fetch info with status code: {info_res.status_code}')

    return DomainAttestation.model_validate({
        'intel_quote': intel_quote_res.json()['quote'],
        'domain': domain,
        'cert': cert_res.text,
        'acme_account': acme_account_res.text,
        'sha256sum': sha256sum_res.text,
        'info': info_res.json()
    })

