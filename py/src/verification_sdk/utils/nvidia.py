import requests

from .common import decode_jwt
from .consts import NVIDIA_GPU_VERIFIER_API_URL
from .errors import VerificationError


def fetch_nvidia_gpu_verification_data(payload: str) -> dict:
    try:
        response = requests.post(
            NVIDIA_GPU_VERIFIER_API_URL,
            data=payload,
            headers={"content-type": "application/json"},
        )
    except Exception as e:
        raise VerificationError("Failed to fetch Nvidia GPU verification data") from e

    if not response.ok:
        raise VerificationError(
            f"Failed to fetch Nvidia GPU verification data with status code {response.status_code}"
        )

    # Raw format is expected to be:
    # [
    #   ["JWT", "<jwt>"],
    #   { "GPU-0": "<jwt>", "GPU-1": "<jwt>", ... }
    # ]
    verification_data_raw = response.json()

    return {
        "JWT": decode_jwt(verification_data_raw[0][1]),
        "GPU": {key: decode_jwt(value) for key, value in verification_data_raw[1].items()},
    }

