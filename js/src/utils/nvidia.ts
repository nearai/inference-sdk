import type { NvidiaEvidenceVerifier } from '../types/verification';
import { decodeNrasOverallAttestationVerdict } from '../boundaries/nvidia';
import { NVIDIA_GPU_VERIFIER_API_URL } from './consts';
import { VerificationError } from './errors';

/**
 * Default NVIDIA NRAS adapter. It verifies through the NRAS HTTPS service and
 * accepts only the documented boolean overall JWT claim. It does not
 * independently verify that JWT's signature. Supply a custom verifier when
 * local JWT/EAT validation is required. The caller verifies payload freshness
 * before this adapter runs.
 */
export const nvidiaNrasVerifier: NvidiaEvidenceVerifier = async (
  nvidiaPayload,
): Promise<void> => {
  const response = await fetchNras(nvidiaPayload);

  if (!response.ok) {
    throw new VerificationError({
      code: 'gpu.nras_request_failed',
      details: { reason: 'http_status', status: response.status },
      retryable: isRetryableNrasStatus(response.status),
    });
  }

  const raw = await getNrasJson(response);
  if (decodeNrasOverallAttestationVerdict(raw)) {
    return;
  }
  throw new VerificationError({
    code: 'gpu.attestation_rejected',
    details: { source: 'nras' },
  });
};

async function fetchNras(nvidiaPayload: string): Promise<Response> {
  try {
    return await fetch(NVIDIA_GPU_VERIFIER_API_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: nvidiaPayload,
    });
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'gpu.nras_request_failed',
        details: { reason: 'transport' },
        retryable: true,
      },
      { cause },
    );
  }
}

async function getNrasJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch (cause) {
    throw invalidNrasResponse('invalid_json', cause);
  }
}

function invalidNrasResponse(
  reason: 'invalid_json',
  cause?: unknown,
): VerificationError {
  return new VerificationError(
    {
      code: 'gpu.nras_response_invalid',
      details: { reason },
    },
    cause === undefined ? undefined : { cause },
  );
}

function isRetryableNrasStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}
