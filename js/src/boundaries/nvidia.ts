import * as v from 'valibot';
import {
  NrasOverallAttestationJwtClaimsSchema,
  NrasResponseSchema,
  NvidiaJwksSchema,
} from '../schemas';
import type {
  NrasOverallAttestationJwtClaims,
  NvidiaJwks,
} from '../types/nvidia';
import { VerificationError } from '../utils/errors';

export function decodeNvidiaJwks(value: unknown): NvidiaJwks {
  const parsed = v.safeParse(NvidiaJwksSchema, value);
  if (!parsed.success) throw invalidNrasResponse('invalid_jwks');
  return parsed.output;
}

/** Read the JWT without treating its unsigned claims as evidence. */
export function decodeNrasOverallAttestationJwt(value: unknown): string {
  const parsed = v.safeParse(NrasResponseSchema, value);
  if (!parsed.success) {
    throw invalidNrasResponse('invalid_schema');
  }
  return parsed.output[0][1];
}

/** Called after JWT signature and registered claims have been verified. */
export function decodeNrasOverallAttestationClaims(
  value: unknown,
): NrasOverallAttestationJwtClaims {
  const parsed = v.safeParse(NrasOverallAttestationJwtClaimsSchema, value);
  if (!parsed.success) {
    throw new VerificationError({
      code: 'gpu.jwt_verification_failed',
      details: { reason: 'invalid_claims' },
    });
  }
  return parsed.output;
}

function invalidNrasResponse(
  reason: 'invalid_jwks' | 'invalid_schema',
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
