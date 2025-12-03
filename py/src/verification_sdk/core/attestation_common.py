from __future__ import annotations

from typing import Any, Dict, Iterable, List

import requests

from ..types.attestation_common import TcbInfo
from ..utils.common import hex_to_bytes, json_loads
from ..utils.consts import SIGSTORE_SEARCH_API_URL, TIMEOUT
from ..utils.errors import VerificationError


def verify_intel_quote_report_data_for_attestation_report(
    report_data: str,
    request_nonce: str,
    signing_address: str,
) -> None:
    """Verify that TDX report data binds the signing address and request nonce."""
    report_raw = hex_to_bytes(report_data)
    signing_address_raw = hex_to_bytes(signing_address)

    embedded_address = report_raw[:32]
    embedded_nonce = report_raw[32:]

    addr_padded = signing_address_raw.ljust(32, b"\x00")

    if embedded_address != addr_padded:
        raise VerificationError("Signing address mismatching")

    if embedded_nonce != hex_to_bytes(request_nonce):
        raise VerificationError("Request nonce mismatching")


def _tcb_info_to_compose(tcb_info: TcbInfo | str | Dict[str, Any]) -> str:
    if isinstance(tcb_info, str):
        try:
            data = json_loads(tcb_info)
        except Exception as exc:  # pragma: no cover - defensive
            raise VerificationError("Invalid tcb info") from exc
    elif isinstance(tcb_info, TcbInfo):
        data = {"app_compose": tcb_info.app_compose}
    else:
        data = tcb_info

    compose = data.get("app_compose")
    if not isinstance(compose, str):
        raise VerificationError("Invalid tcb info: missing app_compose")
    return compose


def get_compose_from_tcb_info(tcb_info: TcbInfo | str | Dict[str, Any]) -> str:
    """Extract compose string from TcbInfo or its JSON representation."""
    return _tcb_info_to_compose(tcb_info)


def _get_sigstore_links_from_compose(compose: str) -> List[str]:
    import re

    digests_iter: Iterable[str] = (
        m.group(1) for m in re.finditer(r"@sha256:([0-9a-f]{64})", compose)
    )
    digests = list(dict.fromkeys(digests_iter))  # preserve order & dedupe

    if not digests:
        raise VerificationError("Failed to get sigstore links from compose")

    return [f"{SIGSTORE_SEARCH_API_URL}/?hash=sha256:{d}" for d in digests]


def verify_compose(compose: str) -> None:
    """Verify that all Sigstore links referenced in compose are reachable."""
    links = _get_sigstore_links_from_compose(compose)
    for link in links:
        try:
            res = requests.head(link, allow_redirects=True, timeout=TIMEOUT)
        except requests.RequestException as exc:  # pragma: no cover - network
            raise VerificationError(f"Verify sigstore link {link} timeout") from exc

        if res.status_code >= 400:
            raise VerificationError(
                f"Failed to verify sigstore link {link} with status code {res.status_code}"
            )


