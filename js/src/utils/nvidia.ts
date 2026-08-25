import { GpuVerifier } from '../types/verification';
import { NVIDIA_GPU_VERIFIER_API_URL, TIMEOUT } from './consts';
import { decodeJwt } from './common';
import { VerificationError } from './errors';
import { fetchTimeout } from './fetch';

/**
 * Default NVIDIA NRAS adapter. It verifies through the NRAS HTTPS service and
 * accepts only the documented boolean overall JWT claim. It does not
 * independently verify that JWT's signature. Supply a custom GpuVerifier when
 * local JWT/EAT validation is required. The caller verifies payload freshness
 * before this adapter runs.
 */
export const nvidiaNrasVerifier: GpuVerifier = {
  async verify(nvidiaPayload: string): Promise<void> {
    const response = await fetchTimeout(NVIDIA_GPU_VERIFIER_API_URL, TIMEOUT, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: nvidiaPayload,
    });

    if (!response.ok) {
      throw new VerificationError(
        `NVIDIA NRAS returned HTTP ${response.status}`,
      );
    }

    const raw: unknown = await response.json();
    const jwt = getOverallJwt(raw);
    const claims = decodeJwt(jwt);
    const rawVerdict = claims['x-nvidia-overall-att-result'];
    if (rawVerdict === true) {
      return;
    }
    if (rawVerdict === false) {
      throw new VerificationError(
        'NVIDIA NRAS reported a failed overall attestation result',
      );
    }
    throw new VerificationError(
      'NVIDIA NRAS overall attestation result must be a boolean',
    );
  },
};

function getOverallJwt(value: unknown): string {
  if (!Array.isArray(value) || !Array.isArray(value[0])) {
    throw new VerificationError('Unexpected NVIDIA NRAS response format');
  }
  const [label, jwt] = value[0];
  if (label !== 'JWT' || typeof jwt !== 'string') {
    throw new VerificationError('Unexpected NVIDIA NRAS overall evidence');
  }
  return jwt;
}
