import aiohttp

from .common import decode_jwt
from .consts import NVIDIA_GPU_VERIFIER_API_URL
from .errors import VerificationError


async def fetch_nvidia_gpu_verification_data(payload: str) -> dict:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                NVIDIA_GPU_VERIFIER_API_URL,
                data=payload,
                headers={'content-type': 'application/json'},
            ) as response:
                if not response.ok:
                    raise VerificationError(
                        f'Failed to fetch Nvidia GPU verification data with status code {response.status}'
                    )

                # Raw format is expected to be:
                # [
                #   ['JWT', '<jwt>'],
                #   { 'GPU-0': '<jwt>', 'GPU-1': '<jwt>', ... }
                # ]
                verification_data_raw = await response.json()

                return {
                    'JWT': decode_jwt(verification_data_raw[0][1]),
                    'GPU': {key: decode_jwt(value) for key, value in verification_data_raw[1].items()},
                }
    except Exception as e:
        raise VerificationError('Failed to fetch Nvidia GPU verification data') from e

