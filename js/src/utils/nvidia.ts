import { Buffer } from 'buffer';
import { createLocalJWKSet, errors, jwtVerify } from 'jose';
import {
  decodeNrasOverallAttestationClaims,
  decodeNrasOverallAttestationJwt,
  decodeNvidiaJwks,
} from '../boundaries/nvidia';
import { NVIDIA_GPU_VERIFIER_API_URL } from './consts';
import { isVerificationError, VerificationError } from './errors';
import type { VerificationFailure } from './errors';

type NvidiaJwksResolver = ReturnType<typeof createLocalJWKSet>;
type NvidiaJwtFailureReason = Extract<
  VerificationFailure,
  {
    code: 'gpu.jwt_verification_failed';
  }
>['details']['reason'];

const NVIDIA_ISSUER = 'https://nras.attestation.nvidia.com';
const NVIDIA_JWKS_URL = `${NVIDIA_ISSUER}/.well-known/jwks.json`;

/**
 * Verify NRAS's overall EAT JWT using NVIDIA's public JWKS. Only ES384 is
 * accepted, matching NVIDIA's remote verifier. Detached device claims are not
 * consumed here; the signed overall result is the SDK's GPU verdict.
 */
export async function nvidiaNrasVerifier(
  nvidiaPayload: string,
  nonce: string,
): Promise<void> {
  const [token, jwks] = await Promise.all([
    fetchNrasToken(nvidiaPayload),
    fetchNvidiaJwks(),
  ]);
  let payload: unknown;
  try {
    const verified = await jwtVerify(
      token,
      (header, signature) => {
        if (header.kid === undefined) throw jwtFailure('key_not_found');
        return jwks(header, signature);
      },
      {
        algorithms: ['ES384'],
        issuer: NVIDIA_ISSUER,
        requiredClaims: ['exp', 'nbf', 'iat'],
      },
    );
    payload = verified.payload;
  } catch (cause) {
    if (isVerificationError(cause)) throw cause;
    if (cause instanceof errors.JWTExpired) throw jwtFailure('expired', cause);
    if (cause instanceof errors.JWTClaimValidationFailed) {
      throw jwtFailure(
        cause.claim === 'nbf' && cause.reason === 'check_failed'
          ? 'not_yet_valid'
          : 'invalid_claims',
        cause,
      );
    }
    if (cause instanceof errors.JWTInvalid)
      throw jwtFailure('invalid_claims', cause);
    if (cause instanceof errors.JWKSNoMatchingKey)
      throw jwtFailure('key_not_found', cause);
    if (cause instanceof errors.JOSEAlgNotAllowed)
      throw jwtFailure('unsupported_algorithm', cause);
    throw jwtFailure('invalid_signature', cause);
  }
  const claims = decodeNrasOverallAttestationClaims(payload);
  if (claims.iat > Date.now() / 1000) throw jwtFailure('not_yet_valid');
  const expectedNonce = nonce.replace(/^0x/i, '');
  if (
    !Buffer.from(claims.eat_nonce, 'hex').equals(
      Buffer.from(expectedNonce, 'hex'),
    )
  ) {
    throw jwtFailure('nonce_mismatch');
  }
  if (claims['x-nvidia-overall-att-result']) {
    return;
  }
  throw new VerificationError({
    code: 'gpu.attestation_rejected',
    details: { source: 'nras' },
  });
}

async function fetchNrasToken(nvidiaPayload: string): Promise<string> {
  const response = await fetchNras(nvidiaPayload);
  if (!response.ok) {
    throw new VerificationError({
      code: 'gpu.nras_request_failed',
      details: { reason: 'http_status', status: response.status },
      retryable: isRetryableNrasStatus(response.status),
    });
  }
  const raw = await getNrasJson(response);
  return decodeNrasOverallAttestationJwt(raw);
}

async function fetchNvidiaJwks(): Promise<NvidiaJwksResolver> {
  let response: Response;
  try {
    response = await fetch(NVIDIA_JWKS_URL);
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'gpu.jwks_request_failed',
        details: { reason: 'transport' },
        retryable: true,
      },
      { cause },
    );
  }
  if (!response.ok) {
    throw new VerificationError({
      code: 'gpu.jwks_request_failed',
      details: { reason: 'http_status', status: response.status },
      retryable: isRetryableNrasStatus(response.status),
    });
  }
  try {
    const raw: unknown = await response.json();
    return createLocalJWKSet(decodeNvidiaJwks(raw));
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'gpu.nras_response_invalid',
        details: { reason: 'invalid_jwks' },
      },
      { cause },
    );
  }
}

function jwtFailure(
  reason: NvidiaJwtFailureReason,
  cause?: unknown,
): VerificationError {
  return new VerificationError(
    {
      code: 'gpu.jwt_verification_failed',
      details: { reason },
    },
    cause === undefined ? undefined : { cause },
  );
}

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
