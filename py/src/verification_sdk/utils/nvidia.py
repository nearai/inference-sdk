import base64
import requests
import json

from typing import Any, Dict

from .common import decode_jwt
from .consts import NVIDIA_GPU_VERIFIER_API_URL
from .errors import VerificationError


def _base64url_decode_jwt_payload(jwt_token: str) -> str:
    payload_b64 = jwt_token.split(".")[1]
    padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
    return base64.urlsafe_b64decode(padded).decode()


def fetch_nvidia_gpu_verification_data(payload: str) -> Dict[str, Any]:
    """Submit GPU evidence to NVIDIA NRAS for verification.

    Returns a dict compatible with NvidiaGpuVerificationData in the JS SDK:

    {
        "JWT": <decoded JWT payload>,
        "GPU": { gpu_id: <decoded JWT payload>, ... },
    }
    """
    try:
        response = requests.post(
            NVIDIA_GPU_VERIFIER_API_URL,
            data=payload,
            headers={"content-type": "application/json"},
            timeout=30,
        )
    except requests.RequestException as exc:  # pragma: no cover - network issues
        raise VerificationError("Failed to fetch Nvidia GPU verification data") from exc

    if not response.ok:
        raise VerificationError(
            f"Failed to fetch Nvidia GPU verification data with status code {response.status_code}"
        )

    verification = json.loads(response.text)

    # Raw format is expected to be:
    # [
    #   ["JWT", "<jwt_token>"],
    #   { "<gpu_id>": "<jwt_token>", ... }
    # ]
    if not isinstance(verification, list) or len(verification) < 2:
        raise VerificationError("Unexpected Nvidia verification response format")

    header_entry = verification[0]
    gpu_map_entry = verification[1]

    if not (isinstance(header_entry, list) and len(header_entry) == 2):
        raise VerificationError("Unexpected Nvidia JWT entry format")

    jwt_token = header_entry[1]
    jwt_decoded = decode_jwt(jwt_token)

    if not isinstance(gpu_map_entry, dict):
        raise VerificationError("Unexpected Nvidia GPU map format")

    gpu_decoded: Dict[str, Any] = {}
    for key, value in gpu_map_entry.items():
        gpu_decoded[str(key)] = decode_jwt(str(value))

    return {
        "JWT": jwt_decoded,
        "GPU": gpu_decoded,
    }


