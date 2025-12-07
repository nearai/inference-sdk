import json

import pydash
from dcap_qvl import get_collateral_and_verify

from .common import hex_to_bytes
from .consts import INTEL_PCCS_API_URL
from .errors import VerificationError


async def fetch_intel_tdx_verification_data(quote: str) -> dict:
    quote_raw = hex_to_bytes(quote)

    try:
        verified_report = await get_collateral_and_verify(quote_raw, INTEL_PCCS_API_URL)
    except Exception as e:
        raise VerificationError("Failed to verify Intel quote") from e

    verified = verified_report.status == "UpToDate"

    verification_data_raw = json.loads(verified_report.to_json())
    reportdata = pydash.get(verification_data_raw, "report.TD10.report_data", "")
    mrconfig = pydash.get(verification_data_raw, "report.TD10.mr_config_id", "")

    return {
        "quote": {
            "verified": verified,
            "body": {
                "reportdata": f"0x{reportdata}",
                "mrconfig": f"0x{mrconfig}",
            },
        }
    }

