import { Buffer } from 'buffer';
import * as v from 'valibot';
import {
  NrasJwtPayloadSchema,
  NrasOverallAttestationJwtClaimsSchema,
  NrasResponseSchema,
} from '../schemas';
import type {
  NrasOverallAttestationJwtClaims,
  NrasResponse,
} from '../types/nvidia';
import { VerificationError } from '../utils/errors';

const OverallAttestationResultClaim = 'x-nvidia-overall-att-result';

/** Decode the documented boolean overall-attestation verdict from an NRAS response. */
export function decodeNrasOverallAttestationVerdict(value: unknown): boolean {
  const jwt = parseNrasResponse(value)[0][1];
  const payload = decodeJwtPayload(jwt);
  const claims = parseNrasOverallAttestationJwtClaims(payload);
  return claims[OverallAttestationResultClaim];
}

function parseNrasResponse(value: unknown): NrasResponse {
  const parsed = v.safeParse(NrasResponseSchema, value);
  if (!parsed.success) {
    throw invalidNrasResponse('invalid_schema');
  }
  return parsed.output;
}

function decodeJwtPayload(jwt: string): unknown {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw invalidNrasResponse('invalid_jwt');
  }

  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch (cause) {
    throw invalidNrasResponse('invalid_jwt', cause);
  }

  const parsed = v.safeParse(NrasJwtPayloadSchema, payload);
  if (!parsed.success) {
    throw invalidNrasResponse('invalid_jwt');
  }
  return parsed.output;
}

function parseNrasOverallAttestationJwtClaims(
  value: unknown,
): NrasOverallAttestationJwtClaims {
  const parsed = v.safeParse(NrasOverallAttestationJwtClaimsSchema, value);
  if (!parsed.success) {
    throw invalidNrasResponse('invalid_verdict_type');
  }
  return parsed.output;
}

function invalidNrasResponse(
  reason: 'invalid_jwt' | 'invalid_schema' | 'invalid_verdict_type',
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
