import re

from ..types.attestation_common import TcbInfo
from ..utils.common import hex_to_bytes
from ..utils.consts import SIGSTORE_SEARCH_API_URL, TIMEOUT
from ..utils.errors import VerificationError
from ..utils.fetch import fetch


def verify_intel_quote_report_data_for_attestation_report(
    report_data: str,
    request_nonce: str,
    signing_address: str,
):
    report_raw = hex_to_bytes(report_data)
    signing_address_raw = hex_to_bytes(signing_address)

    embedded_address = report_raw[:32]
    embedded_nonce = report_raw[32:]

    signing_address_verified = embedded_address == signing_address_raw.ljust(
        32, b'\x00'
    )

    if not signing_address_verified:
        raise VerificationError('Signing address mismatching')

    request_nonce_verified = embedded_nonce == hex_to_bytes(request_nonce)

    if not request_nonce_verified:
        raise VerificationError('Request nonce mismatching')


def get_compose_from_tcb_info(tcb_info: str | TcbInfo) -> str:
    if isinstance(tcb_info, str):
        try:
            tcb_info = TcbInfo.model_validate_json(tcb_info)
        except Exception as e:
            raise VerificationError('Invalid tcb info') from e

    return tcb_info.app_compose


async def verify_compose(compose: str, image_names_of_sigstore_hash: list[str]):
    hashes = get_sigstore_hashes_from_compose(compose, image_names_of_sigstore_hash)
    for h in hashes:
        await verify_sigstore_hash(h)


def get_sigstore_hashes_from_compose(
    compose: str,
    image_names_of_sigstore_hash: list[str],
) -> list[str]:
    names = set(image_names_of_sigstore_hash)

    found_names: set[str] = set()
    found_digests: list[str] = []

    # Match "<image-name>@sha256:<64-hex-digest>"
    for m in re.finditer(r'([^@\s]+)@sha256:([0-9a-f]{64})', compose):
        name = m.group(1)
        digest = m.group(2)

        if name not in names:
            continue

        found_names.add(name)
        found_digests.append(digest)

    missing_names = [n for n in image_names_of_sigstore_hash if n not in found_names]

    if missing_names:
        raise VerificationError(
            f'Missing sigstore hash for image: {", ".join(missing_names)}'
        )

    return found_digests


async def verify_sigstore_hash(_hash: str):
    response = await fetch(
        SIGSTORE_SEARCH_API_URL,
        method='POST',
        data={'hash': _hash},
        headers={'content-type': 'application/json'},
        timeout=TIMEOUT,
    )

    if not response.ok:
        raise VerificationError(
            f'Failed to verify sigstore hash with status code {response.status}'
        )

    outputs = response.json()

    if not isinstance(outputs, list) or not outputs:
        raise VerificationError(f'Invalid sigstore hash {_hash}')
