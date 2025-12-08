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

    response = await fetch(
        url,
        headers={"authorization": f'Bearer {api_key}'},
        raise_if_not_ok=True
    )

    return AttestationReport.model_validate_json(response.bytes())


async def fetch_chat_signature(
    api_url: str,
    api_key: str,
    chat_id: str,
    model: str,
    signing_algo: SigningAlgo,
) -> ChatSignature:
    url = f'{api_url}/signature/{chat_id}?model={quote(model)}&signing_algo={signing_algo}'

    response = await fetch(
        url,
        headers={"authorization": f'Bearer {api_key}'},
        raise_if_not_ok=True
    )

    return ChatSignature.model_validate_json(response.bytes())


async def chat_completions(
    api_url: str,
    api_key: str,
    request_body: dict,
) -> ChatCompletionsResponse:
    request_body_raw = json.dumps(request_body).encode()

    response = await fetch(
        f'{api_url}/chat/completions',
        method='POST',
        data=request_body_raw,
        headers={
            'authorization': f'Bearer {api_key}',
            'content-type': 'application/json',
        },
    )

    if not response.ok:
        raise ValueError(f'Failed to chat with status code: {response.status}')

    response_body_raw = response.bytes()

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

    intel_quote_res, cert_res, acme_account_res, sha256sum_res, info_res = await asyncio.gather(
        fetch(intel_quote_url, raise_if_not_ok=True),
        fetch(cert_url, raise_if_not_ok=True),
        fetch(acme_account_url, raise_if_not_ok=True),
        fetch(sha256sum_url, raise_if_not_ok=True),
        fetch(info_url, raise_if_not_ok=True),
    )

    return DomainAttestation.model_validate({
        'intel_quote': intel_quote_res.json()['quote'],
        'domain': domain,
        'cert': cert_res.text(),
        'acme_account': acme_account_res.text(),
        'sha256sum': sha256sum_res.text(),
        'info': info_res.json()
    })

