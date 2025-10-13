import {
  NvidiaGpuVerificationRaw,
  NvidiaGpuVerification,
} from '../types/nvidia';
import { decodeJwt } from 'jose';
import { mapRecord } from './common';

export function isNvidiaGpuVerified(
  verification: NvidiaGpuVerification,
): boolean {
  const result = verification.JWT['x-nvidia-overall-att-result'];
  if (typeof result !== 'boolean') {
    throw Error('Unreachable: `x-nvidia-overall-att-result` is not a boolean');
  }
  return result;
}

export async function verifyNvidiaGpu(
  payload: string,
): Promise<NvidiaGpuVerification> {
  const response = await fetch(
    'https://nras.attestation.nvidia.com/v3/attest/gpu',
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: payload,
    },
  );

  if (!response.ok) {
    throw Error(`Verify Nvidia GPU failed with status code ${response.status}`);
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
