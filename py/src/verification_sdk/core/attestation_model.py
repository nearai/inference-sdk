import pydash

from ..core.attestation_common import (
    get_compose_from_tcb_info,
    verify_compose,
    verify_intel_quote_report_data_for_attestation_report,
)
from ..types.attestation_model import ModelAttestation
from ..utils.errors import VerificationError
from ..utils.intel import fetch_intel_tdx_verification_data
from ..utils.nvidia import fetch_nvidia_gpu_verification_data


async def verify_model_attestation(attestation: ModelAttestation):
    intel_tdx_verification_data = await fetch_intel_tdx_verification_data(attestation.intel_quote)
    verify_intel_tdx_for_model(
        intel_tdx_verification_data,
        attestation.request_nonce,
        attestation.signing_address,
    )

    nvidia_data = fetch_nvidia_gpu_verification_data(attestation.nvidia_payload)
    verify_nvidia_gpu_for_model(nvidia_data)

    verify_compose(get_compose_from_tcb_info(attestation.info.tcb_info))


def verify_intel_tdx_for_model(
    verification_data: dict,
    request_nonce: str,
    signing_address: str,
):
    if not pydash.get(verification_data, 'quote.verified'):
        raise VerificationError('Intel quote not verified')

    report_data = pydash.get(verification_data, 'quote.body.reportdata')

    if not isinstance(report_data, str):
        raise VerificationError('Bad reportdata')

    verify_intel_quote_report_data_for_attestation_report(
        report_data,
        request_nonce,
        signing_address,
    )


def verify_nvidia_gpu_for_model(verification_data: dict):
    result = pydash.get(verification_data, 'JWT.x-nvidia-overall-att-result')
    if not result:
        raise VerificationError('Nvidia GPU not verified')

