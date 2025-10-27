import {
  NvidiaGpuVerificationRaw,
  NvidiaGpuVerification,
} from '../types/nvidia';
import { decodeJwt, mapRecord } from './common';
import { NVIDIA_GPU_VERIFIER_API_URL } from './consts';
import { VerificationError } from './errors';

export function assertNvidiaGpuVerified(verification: NvidiaGpuVerification) {
  const result = verification.JWT['x-nvidia-overall-att-result'];
  if (!result) {
    throw new VerificationError('Failed to verify Nvidia GPU');
  }
}

export async function verifyNvidiaGpu(
  payload: string,
): Promise<NvidiaGpuVerification> {
  const response = await fetch(NVIDIA_GPU_VERIFIER_API_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: payload,
  });

  if (!response.ok) {
    throw new VerificationError(
      `Verify Nvidia GPU failed with status code ${response.status}`,
    );
  }

  const verification = await response.json();

  return parseNvidiaGpuVerification(verification);
}

function parseNvidiaGpuVerification(
  verification: NvidiaGpuVerificationRaw,
): NvidiaGpuVerification {
  return {
    JWT: decodeJwt(verification[0][1]),
    GPU: mapRecord(verification[1], (key, value) => decodeJwt(value)),
  };
}
