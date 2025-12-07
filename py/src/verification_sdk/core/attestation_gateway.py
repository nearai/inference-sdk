import pydash
import requests

from typing import Optional

from ..core.attestation_common import (
    get_compose_from_tcb_info,
    verify_compose,
    verify_intel_quote_report_data_for_attestation_report,
)
from ..types.attestation_gateway import GatewayAttestation
from ..utils.consts import ETHEREUM_ZERO_ADDRESS
from ..utils.errors import VerificationError
from ..utils.intel import fetch_intel_tdx_verification_data


async def verify_gateway_attestation(attestation: GatewayAttestation, domain: str):
    verification_data = await fetch_intel_tdx_verification_data(attestation.intel_quote)

    verify_intel_tdx_for_gateway(
        verification_data,
        attestation.request_nonce,
        attestation.signing_address,
    )

    verify_vpc_for_gateway(
        domain,
        attestation.vpc.vpc_server_app_id,
        attestation.vpc.vpc_hostname,
    )

    verify_compose(get_compose_from_tcb_info(attestation.info.tcb_info))


def verify_intel_tdx_for_gateway(
    verification_data: dict,
    request_nonce: str,
    signing_address: Optional[str] = ETHEREUM_ZERO_ADDRESS,
):
    if not pydash.get(verification_data, "quote.verified"):
        raise VerificationError('Intel quote not verified')

    report_data = pydash.get(verification_data, "quote.body.reportdata")

    if not isinstance(report_data, str):
        raise VerificationError('Bad reportdata')

    verify_intel_quote_report_data_for_attestation_report(
        report_data,
        request_nonce,
        signing_address,
    )


def verify_vpc_for_gateway(
    domain: str,
    vpc_server_app_id: str,
    vpc_hostname: str,
):
    url = f"https://{domain}/evidences/vpc.json"

    try:
        res = requests.get(url)
    except Exception as e:
        raise VerificationError("Failed to fetch VPC info") from e

    if not res.ok:
        raise VerificationError(
            f"Failed to fetch VPC info with status code {res.status_code}"
        )

    vpc_info = res.json()

    if vpc_info.get("vpc_server_app_id") != vpc_server_app_id:
        raise VerificationError("vpc_server_app_id mismatching")

    nodes = vpc_info.get("nodes")

    if not nodes or vpc_hostname not in nodes:
        raise VerificationError("vpc_hostname mismatching")

