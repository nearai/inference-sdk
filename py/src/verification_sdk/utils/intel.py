from __future__ import annotations

from typing import Any, Dict

from dcap_qvl import get_collateral_and_verify

from .common import hex_to_bytes, json_loads
from .errors import VerificationError


def fetch_intel_tdx_verification_data(quote: str) -> Dict[str, Any]:
    """Fetch and verify Intel TDX quote using local dcap-qvl, mirroring JS structure."""
    quote_raw = hex_to_bytes(quote)

    try:
        result = get_collateral_and_verify(quote_raw)
    except Exception as e:
        raise VerificationError("Failed to verify Intel quote") from e

    result_json = json_loads(result.to_json())

    verified = result.status == "UpToDate"

    reportdata = ""
    mrconfig = ""
    td10 = result_json.get("report", {}).get("TD10")
    if td10:
        reportdata = td10.get("report_data", "") or ""
        mrconfig = td10.get("mr_config_id", "") or ""

    return {
        "quote": {
            "body": {
                "reportdata": reportdata,
                "mrconfig": mrconfig,
            },
            "verified": verified,
        }
    }


