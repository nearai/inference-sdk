import { Buffer } from 'buffer';
import {
  Quote,
  getCollateral,
  type Collateral,
  type VerifiedReport,
  verify,
} from '@phala/dcap-qvl';
import type { VerifiedTdxQuote } from '../types/verification';
import { QuoteVerificationResultSchema } from '../schemas';
import { getIntelPccsApiUrl, hexToBuffer } from './common';
import { isVerificationError, VerificationError } from './errors';
import { parseQuoteResult } from './schema';

/**
 * Verify an Intel TDX quote using DCAP and expose only the measurements needed
 * by the provider-agnostic verification core.
 */
export async function verifyDcapQuote(
  quote: string,
): Promise<VerifiedTdxQuote> {
  let quoteBytes: Uint8Array;
  try {
    quoteBytes = hexToBuffer(quote);
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'quote',
        code: 'quote.verification_failed',
        details: { reason: 'invalid_encoding' },
      },
      { cause },
    );
  }

  try {
    Quote.parse(quoteBytes);
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'quote',
        code: 'quote.verification_failed',
        details: { reason: 'invalid_quote' },
      },
      { cause },
    );
  }

  let collateral: Collateral;
  try {
    collateral = await getCollateral(getIntelPccsApiUrl(), quoteBytes);
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'quote',
        code: 'quote.collateral_unavailable',
        retryable: true,
      },
      { cause },
    );
  }

  let verifiedReport: VerifiedReport;
  try {
    verifiedReport = verify(
      quoteBytes,
      collateral,
      Math.floor(Date.now() / 1000),
    );
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'quote',
        code: 'quote.verification_failed',
        details: { reason: 'verifier_error' },
      },
      { cause },
    );
  }

  let td10: unknown;
  try {
    td10 = verifiedReport.report.asTd10();
  } catch (cause) {
    throw invalidDcapResult(cause);
  }
  if (!td10) {
    throw new VerificationError({
      phase: 'quote',
      code: 'quote.unsupported_report_type',
      details: { expected: 'TD10' },
    });
  }

  let result: unknown;
  try {
    result = {
      tcbStatus: verifiedReport.status,
      advisoryIds: verifiedReport.advisory_ids,
      debugEnabled: getDebugEnabled(
        (td10 as { tdAttributes: unknown }).tdAttributes,
      ),
      reportData: (td10 as { reportData: unknown }).reportData,
      mrConfigId: (td10 as { mrConfigId: unknown }).mrConfigId,
      rtMr3: (td10 as { rtMr3: unknown }).rtMr3,
    };
  } catch (cause) {
    throw invalidDcapResult(cause);
  }
  return normalizeVerifiedTdxQuote(result);
}

/** Validate quote-adapter output and normalize its byte fields to Buffers. */
export function normalizeVerifiedTdxQuote(value: unknown): VerifiedTdxQuote {
  const quote = parseQuoteResult(QuoteVerificationResultSchema, value);
  return {
    tcbStatus: quote.tcbStatus,
    advisoryIds: [...quote.advisoryIds],
    debugEnabled: quote.debugEnabled,
    reportData: Buffer.from(quote.reportData),
    mrConfigId: Buffer.from(quote.mrConfigId),
    rtMr3: Buffer.from(quote.rtMr3),
  };
}

function getDebugEnabled(value: unknown): boolean {
  const attributes = requireBytes(value, 'tdAttributes');
  if (attributes.length < 1) {
    throw new VerificationError({
      phase: 'quote',
      code: 'quote.invalid_result',
      details: {
        path: 'tdAttributes',
        expected: 'at least one byte',
        actual: describeValue(value),
      },
    });
  }
  return (attributes[0] & 0x01) !== 0;
}

function requireBytes(value: unknown, path: string): Buffer {
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  throw new VerificationError({
    phase: 'quote',
    code: 'quote.invalid_result',
    details: { path, expected: 'Uint8Array', actual: describeValue(value) },
  });
}

function invalidDcapResult(cause: unknown): VerificationError {
  if (isVerificationError(cause)) {
    return cause;
  }
  return new VerificationError(
    {
      phase: 'quote',
      code: 'quote.invalid_result',
      details: {
        path: 'dcap_result',
        expected: 'verified TDX quote',
        actual: 'unreadable',
      },
    },
    { cause },
  );
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
