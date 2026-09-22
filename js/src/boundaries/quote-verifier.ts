import { Buffer } from 'buffer';
import * as v from 'valibot';
import { TdxQuoteVerificationResultSchema } from '../schemas';
import type { VerifiedTdxQuote } from '../types/verification';
import { VerificationError } from '../utils/errors';

/**
 * Quote-verifier boundary.
 *
 * Both the built-in DCAP adapter and a caller-supplied quote verifier return
 * this external shape. Decode it once before the attestation core consumes
 * measurements.
 */
export function decodeTdxQuoteVerifierOutput(value: unknown): VerifiedTdxQuote {
  const parsed = v.safeParse(TdxQuoteVerificationResultSchema, value);
  if (!parsed.success) {
    const issue = parsed.issues[0];
    throw new VerificationError({
      code: 'quote.invalid_result',
      details: {
        path: issuePath(issue),
        expected: describeExpected(issue.expected),
        actual: describeValue(issue.input),
      },
    });
  }

  const quote = parsed.output;
  return {
    tcbStatus: quote.tcbStatus,
    advisoryIds: [...quote.advisoryIds],
    debugEnabled: quote.debugEnabled,
    reportData: Buffer.from(quote.reportData),
    mrConfigId: Buffer.from(quote.mrConfigId),
    ...(quote.mrTd === undefined ? {} : { mrTd: Buffer.from(quote.mrTd) }),
    ...(quote.rtMr0 === undefined ? {} : { rtMr0: Buffer.from(quote.rtMr0) }),
    ...(quote.rtMr1 === undefined ? {} : { rtMr1: Buffer.from(quote.rtMr1) }),
    ...(quote.rtMr2 === undefined ? {} : { rtMr2: Buffer.from(quote.rtMr2) }),
    rtMr3: Buffer.from(quote.rtMr3),
  };
}

function issuePath(issue: v.BaseIssue<unknown>): string {
  const path = v.getDotPath(issue);
  if (!path) {
    return 'quote';
  }
  return path.startsWith('[') ? `quote${path}` : `quote.${path}`;
}

function describeExpected(expected: string | null): string {
  switch (expected) {
    case null:
      return 'valid input';
    case 'Object':
      return 'object';
    case 'Array':
      return 'array';
    case 'string':
      return 'string';
    case 'boolean':
      return 'boolean';
    default:
      return expected;
  }
}

function describeValue(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'array';
  }
  return typeof value;
}
