from ..core.attestation_common import (
    get_compose_from_tcb_info,
    verify_compose,
    verify_intel_quote_report_data_for_attestation_report,
)
from ..types.attestation_model import ModelAttestation
from ..utils.errors import VerificationError
from ..utils.intel import fetch_intel_tdx_verification_data
from ..utils.nvidia import fetch_nvidia_gpu_verification_data


def verify_model_attestation(attestation: ModelAttestation) -> None:
    """Verify model attestation (Intel TDX + NVIDIA GPU + compose)."""
    intel_data = fetch_intel_tdx_verification_data(attestation.intel_quote)
    _verify_intel_tdx_for_model(
        intel_data,
        attestation.request_nonce,
        attestation.signing_address,
    )

    nvidia_data = fetch_nvidia_gpu_verification_data(attestation.nvidia_payload)
    _verify_nvidia_gpu_for_model(nvidia_data)

    compose = get_compose_from_tcb_info(attestation.info.tcb_info)
    verify_compose(compose)


def _verify_intel_tdx_for_model(
    verification_data: dict,
    request_nonce: str,
    signing_address: str,
) -> None:
    quote = verification_data.get("quote", {})
    if not quote.get("verified"):
        raise VerificationError("Intel quote not verified")

    body = quote.get("body", {})
    report_data = body.get("reportdata", "")
    verify_intel_quote_report_data_for_attestation_report(
        report_data,
        request_nonce,
        signing_address,
    )


def _verify_nvidia_gpu_for_model(verification_data: dict) -> None:
    result = verification_data.get("JWT", {}).get("x-nvidia-overall-att-result")
    if not result:
        raise VerificationError("Nvidia GPU not verified")


