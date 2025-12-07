import pydash
from dcap_qvl import get_collateral_and_verify

from .common import hex_to_bytes
from .errors import VerificationError


def fetch_intel_tdx_verification_data(quote: str) -> dict:
    quote_raw = hex_to_bytes(quote)

    try:
        verification_data_raw = get_collateral_and_verify(quote_raw)
    except Exception as e:
        raise VerificationError("Failed to verify Intel quote") from e

    verified = verification_data_raw.status == "UpToDate"

    reportdata = pydash.get(verification_data_raw, "report.TD10.report_data", "")
    mrconfig = pydash.get(verification_data_raw, "report.TD10.mr_config_id", "")

    return {
        "quote": {
            "verified": verified,
            "body": {
                "reportdata": reportdata,
                "mrconfig": mrconfig,
            },
        }
    }

