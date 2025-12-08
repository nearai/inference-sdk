import asyncio
import json
import secrets

from urllib.parse import quote
from verification_sdk import (
    AttestationReport,
    ChatSignature,
    DomainAttestation,
    SigningAlgo,
)

from .fetch import fetch
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

    res = await fetch(
        url,
        headers={'authorization': f'Bearer {api_key}'},
    )

    if not res.ok:
        raise ValueError(
            f'Failed to fetch attestation report with status code: {res.status}'
        )

    return AttestationReport.model_validate_json(res.bytes())


async def fetch_chat_signature(
    api_url: str,
    api_key: str,
    chat_id: str,
    model: str,
    signing_algo: SigningAlgo,
) -> ChatSignature:
    url = f'{api_url}/signature/{chat_id}?model={quote(model)}&signing_algo={signing_algo}'

    res = await fetch(
        url,
        headers={'authorization': f'Bearer {api_key}'},
    )

    if not res.ok:
        raise ValueError(f'Failed to fetch chat signature with status code: {res.status}')

    return ChatSignature.model_validate_json(res.bytes())


async def chat_completions(
    api_url: str,
    api_key: str,
    request_body: dict,
) -> ChatCompletionsResponse:
    request_body_raw = json.dumps(request_body).encode()

    res = await fetch(
        f'{api_url}/chat/completions',
        method='POST',
        data=request_body_raw,
        headers={
            'authorization': f'Bearer {api_key}',
            'content-type': 'application/json',
        },
    )

    if not res.ok:
        raise ValueError(f'Failed to chat with status code: {res.status}')

    response_body_raw = res.bytes()

    if request_body.get('stream'):
        lines = response_body_raw.decode().split('\n')
        first_chunk = json.loads(lines[0][6:])  # data: {...
        chat_id = first_chunk['id']
    else:
        data = json.loads(response_body_raw.decode())
        chat_id = data['id']

    return ChatCompletionsResponse.model_validate(
        {
            'id': chat_id,
            'request_body_raw': request_body_raw,
            'response_body_raw': response_body_raw,
        }
    )


async def fetch_domain_attestation(domain: str) -> DomainAttestation:
    evidences_url = f'https://{domain}/evidences/'

    intel_quote_url = f'{evidences_url}quote.json'
    cert_url = f'{evidences_url}cert-{domain}.pem'
    acme_account_url = f'{evidences_url}acme-account.json'
    sha256sum_url = f'{evidences_url}sha256sum.txt'
    info_url = f'{evidences_url}info.json'

    (
        intel_quote_res,
        cert_res,
        acme_account_res,
        sha256sum_res,
        info_res,
    ) = await asyncio.gather(
        fetch(intel_quote_url),
        fetch(cert_url),
        fetch(acme_account_url),
        fetch(sha256sum_url),
        fetch(info_url),
    )

    if not intel_quote_res.ok:
        raise ValueError(
            f'Failed to fetch Intel quote with status code: {intel_quote_res.status}'
        )

    if not cert_res.ok:
        raise ValueError(
            f'Failed to fetch certificate with status code: {cert_res.status}'
        )

    if not acme_account_res.ok:
        raise ValueError(
            f'Failed to fetch ACME account with status code: {acme_account_res.status}'
        )

    if not sha256sum_res.ok:
        raise ValueError(
            f'Failed to fetch sha256 sum with status code: {sha256sum_res.status}'
        )

    if not info_res.ok:
        raise ValueError(f'Failed to fetch info with status code: {info_res.status}')

    return DomainAttestation.model_validate(
        {
            'intel_quote': intel_quote_res.json()['quote'],
            'domain': domain,
            'cert': cert_res.text(),
            'acme_account': acme_account_res.text(),
            'sha256sum': sha256sum_res.text(),
            'info': info_res.json(),
        }
    )
