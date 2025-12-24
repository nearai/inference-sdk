from ..core.attestation_common import (
    get_compose_from_tcb_info,
    verify_compose,
    verify_intel_quote_report_data_for_attestation_report,
)
from ..types.attestation_model import ModelAttestation
from ..utils.errors import VerificationError
from ..utils.intel import fetch_intel_tdx_verification_data
from ..utils.nvidia import fetch_nvidia_gpu_verification_data


async def verify_model_attestation(
    attestation: ModelAttestation, image_names_of_sigstore_hash: list[str]
):
    intel_tdx_verification_data = await fetch_intel_tdx_verification_data(
        attestation.intel_quote
    )
    verify_intel_tdx_for_model(
        intel_tdx_verification_data,
        attestation.request_nonce,
        attestation.signing_address,
    )

    nvidia_gpu_verification_data = await fetch_nvidia_gpu_verification_data(
        attestation.nvidia_payload
    )
    verify_nvidia_gpu_for_model(nvidia_gpu_verification_data)

    if image_names_of_sigstore_hash:
        await verify_compose(
            get_compose_from_tcb_info(attestation.info.tcb_info),
            image_names_of_sigstore_hash,
        )


def verify_intel_tdx_for_model(
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


def verify_nvidia_gpu_for_model(verification_data: dict):
    result = verification_data.get('JWT', {}).get('x-nvidia-overall-att-result')
    if not result:
        raise VerificationError('NVIDIA GPU not verified')
