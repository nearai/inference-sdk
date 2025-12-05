import requests
import re
import json

from typing import Any

from ..utils.common import hex_to_bytes
from ..utils.consts import SIGSTORE_SEARCH_API_URL, TIMEOUT
from ..utils.errors import VerificationError


def verify_intel_quote_report_data_for_attestation_report(
    report_data: str,
    request_nonce: str,
    signing_address: str,
) -> None:
    report_raw = hex_to_bytes(report_data)
    signing_address_raw = hex_to_bytes(signing_address)

    embedded_address = report_raw[:32]
    embedded_nonce = report_raw[32:]

    signing_address_verified = embedded_address == signing_address_raw.ljust(32, b"\x00")

    if not signing_address_verified:
        raise VerificationError("Signing address mismatching")

    request_nonce_verified = embedded_nonce == hex_to_bytes(request_nonce)

    if not request_nonce_verified:
        raise VerificationError("Request nonce mismatching")


def get_compose_from_tcb_info(tcb_info: str | dict[str, Any]) -> str:
    if isinstance(tcb_info, str):
        try:
            tcb_info = json.loads(tcb_info)
        except Exception as e:
            raise VerificationError("Invalid tcb info") from e

    app_compose = tcb_info.get("app_compose")

    if not isinstance(app_compose, str):
        raise VerificationError("Invalid app_compose")

    return app_compose


def verify_compose(compose: str) -> None:
    links = get_sigstore_links_from_compose(compose)

    for link in links:
        verify_sigstore_link(link)


def get_sigstore_links_from_compose(compose: str) -> list[str]:
    digests_iter = (
        m.group(1) for m in re.finditer(r"@sha256:([0-9a-f]{64})", compose)
    )

    digests = set(digests_iter)

    if not digests:
        raise VerificationError("Failed to get sigstore links from compose")

    return [f"{SIGSTORE_SEARCH_API_URL}/?hash=sha256:{digest}" for digest in digests]


def verify_sigstore_link(link: str):
    try:
        res = requests.head(link, timeout=TIMEOUT)
    except Exception as e:
        raise VerificationError(f"Verify sigstore link {link} timeout") from e

    if res.status_code < 200 or res.status_code >= 300:
        raise VerificationError(
            f"Failed to verify sigstore link {link} with status code {res.status_code}"
        )

