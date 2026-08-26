import { GpuVerifier } from '../types/verification';
import { NVIDIA_GPU_VERIFIER_API_URL, TIMEOUT } from './consts';
import { decodeJwt } from './common';
import { VerificationError } from './errors';
import { FetchTimeoutError, fetchTimeout } from './fetch';

/**
 * Default NVIDIA NRAS adapter. It verifies through the NRAS HTTPS service and
 * accepts only the documented boolean overall JWT claim. It does not
 * independently verify that JWT's signature. Supply a custom GpuVerifier when
 * local JWT/EAT validation is required. The caller verifies payload freshness
 * before this adapter runs.
 */
export const nvidiaNrasVerifier: GpuVerifier = {
  async verify(nvidiaPayload: string): Promise<void> {
    const response = await fetchNras(nvidiaPayload);

    if (!response.ok) {
      throw new VerificationError({
        phase: 'gpu',
        code: 'gpu.nras_request_failed',
        details: { reason: 'http_status', status: response.status },
        retryable: isRetryableNrasStatus(response.status),
      });
    }

    const raw = await getNrasJson(response);
    const jwt = getOverallJwt(raw);
    const claims = decodeOverallJwt(jwt);
    const rawVerdict = claims['x-nvidia-overall-att-result'];
    if (rawVerdict === true) {
      return;
    }
    if (rawVerdict === false) {
      throw new VerificationError({
        phase: 'gpu',
        code: 'gpu.attestation_rejected',
        details: { source: 'nras' },
      });
    }
    throw new VerificationError({
      phase: 'gpu',
      code: 'gpu.nras_response_invalid',
      details: { reason: 'invalid_verdict_type' },
    });
  },
};

function getOverallJwt(value: unknown): string {
  if (!Array.isArray(value) || !Array.isArray(value[0])) {
    throw invalidNrasResponse('invalid_schema');
  }
  const [label, jwt] = value[0];
  if (label !== 'JWT' || typeof jwt !== 'string') {
    throw invalidNrasResponse('invalid_schema');
  }
  return jwt;
}

async function fetchNras(nvidiaPayload: string): Promise<Response> {
  try {
    return await fetchTimeout(NVIDIA_GPU_VERIFIER_API_URL, TIMEOUT, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: nvidiaPayload,
    });
  } catch (cause) {
    const reason = cause instanceof FetchTimeoutError ? 'timeout' : 'transport';
    throw new VerificationError(
      {
        phase: 'gpu',
        code: 'gpu.nras_request_failed',
        details: { reason },
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

function decodeOverallJwt(jwt: string): Record<string, unknown> {
  try {
    return decodeJwt(jwt);
  } catch (cause) {
    throw invalidNrasResponse('invalid_jwt', cause);
  }
}

function invalidNrasResponse(
  reason:
    | 'invalid_json'
    | 'invalid_jwt'
    | 'invalid_schema'
    | 'invalid_verdict_type',
  cause?: unknown,
): VerificationError {
  return new VerificationError(
    {
      phase: 'gpu',
      code: 'gpu.nras_response_invalid',
      details: { reason },
    },
    cause === undefined ? undefined : { cause },
  );
}

function isRetryableNrasStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}
