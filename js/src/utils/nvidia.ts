import {
  NvidiaGpuVerificationDataRaw,
  NvidiaGpuVerificationData,
} from '../types/nvidia';
import { decodeJwt, mapRecord } from './common';
import { NVIDIA_GPU_VERIFIER_API_URL } from './consts';
import { VerificationError } from './errors';

export async function fetchNvidiaGpuVerificationData(
  payload: string,
): Promise<NvidiaGpuVerificationData> {
  const response = await fetch(NVIDIA_GPU_VERIFIER_API_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: payload,
  });

  if (!response.ok) {
    throw new VerificationError(
      `Failed to fetch Nvidia GPU verification data with status code ${response.status}`,
    );
  }

  const verificationData = await response.json();

  return parseNvidiaGpuVerificationData(verificationData);
}

function parseNvidiaGpuVerificationData(
  verification: NvidiaGpuVerificationDataRaw,
): NvidiaGpuVerificationData {
  return {
    JWT: decodeJwt(verification[0][1]),
    GPU: mapRecord(verification[1], (key, value) => decodeJwt(value)),
  };
}
