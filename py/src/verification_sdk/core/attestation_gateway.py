from ..core.attestation_common import (
    get_compose_from_tcb_info,
    verify_compose,
    verify_intel_quote_report_data_for_attestation_report,
)
from ..types.attestation_gateway import GatewayAttestation
from ..utils.consts import ETHEREUM_ZERO_ADDRESS, TIMEOUT
from ..utils.errors import VerificationError
from ..utils.fetch import fetch
from ..utils.intel import fetch_intel_tdx_verification_data


async def verify_gateway_attestation(
    attestation: GatewayAttestation,
    domain: str,
    image_names_of_sigstore_hash: list[str],
):
    verification_data = await fetch_intel_tdx_verification_data(attestation.intel_quote)

    verify_intel_tdx_for_gateway(
        verification_data,
        attestation.request_nonce,
        attestation.signing_address or ETHEREUM_ZERO_ADDRESS,
    )

    await verify_vpc_for_gateway(
        domain,
        attestation.vpc.vpc_server_app_id,
        attestation.vpc.vpc_hostname,
    )

    if image_names_of_sigstore_hash:
        await verify_compose(
            get_compose_from_tcb_info(attestation.info.tcb_info),
            image_names_of_sigstore_hash,
        )


def verify_intel_tdx_for_gateway(
    verification_data: dict,
    request_nonce: str,
    signing_address: str,
):
    if not verification_data.get('quote', {}).get('verified'):
        raise VerificationError('Intel quote not verified')

    report_data = verification_data.get('quote', {}).get('body', {}).get('reportdata')

    if not isinstance(report_data, str):
        raise VerificationError('Bad report data')

    verify_intel_quote_report_data_for_attestation_report(
        report_data,
        request_nonce,
        signing_address,
    )


async def verify_vpc_for_gateway(
    domain: str,
    vpc_server_app_id: str,
    vpc_hostname: str,
):
    url = f'https://{domain}/evidences/vpc.json'

    response = await fetch(url, timeout=TIMEOUT)

    if not response.ok:
        raise VerificationError(
            f'Failed to fetch VPC info with status code {response.status}'
        )

    vpc_info = response.json()

    if vpc_info.get('vpc_server_app_id') != vpc_server_app_id:
        raise VerificationError('vpc_server_app_id mismatching')

    nodes = vpc_info.get('nodes', [])

    if not isinstance(nodes, list) or vpc_hostname not in nodes:
        raise VerificationError('vpc_hostname mismatching')
