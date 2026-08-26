import { Buffer } from 'buffer';
import {
  getCollateral,
  type Collateral,
  type VerifiedReport,
  verify,
} from '@phala/dcap-qvl';
import type { TcbStatus, VerifiedTdxQuote } from '../types/verification';
import { getIntelPccsApiUrl, hexToBuffer } from './common';
import { isVerificationError, VerificationError } from './errors';

const TCB_STATUSES: readonly TcbStatus[] = [
  'UpToDate',
  'SWHardeningNeeded',
  'ConfigurationNeeded',
  'ConfigurationAndSWHardeningNeeded',
  'OutOfDate',
  'OutOfDateConfigurationNeeded',
  'Revoked',
  'Unknown',
];

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

  let collateral: Collateral;
  try {
    collateral = await getCollateral(getIntelPccsApiUrl(), quoteBytes);
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'quote',
        code: 'quote.collateral_unavailable',
        details: {},
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
  try {
    const record = requireQuoteObject(value);
    return {
      tcbStatus: requireTcbStatus(record.tcbStatus, 'tcbStatus'),
      advisoryIds: requireStringArray(record.advisoryIds, 'advisoryIds'),
      debugEnabled: requireBoolean(record.debugEnabled, 'debugEnabled'),
      reportData: requireBytes(record.reportData, 'reportData'),
      mrConfigId: requireBytes(record.mrConfigId, 'mrConfigId'),
      rtMr3: requireBytes(record.rtMr3, 'rtMr3'),
    };
  } catch (cause) {
    if (isVerificationError(cause)) {
      throw cause;
    }
    throw new VerificationError(
      {
        phase: 'quote',
        code: 'quote.invalid_result',
        details: {
          path: 'quote',
          expected: 'VerifiedTdxQuote',
          actual: 'unreadable',
        },
      },
      { cause },
    );
  }
}

function getDebugEnabled(value: unknown): boolean {
  const attributes = requireBytes(value, 'tdAttributes');
  if (attributes.length < 1) {
    throw invalidQuoteResult('tdAttributes', 'at least one byte', value);
  }
  return (attributes[0] & 0x01) !== 0;
}

function requireQuoteObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidQuoteResult('quote', 'object', value);
  }
  return value as Record<string, unknown>;
}

function requireTcbStatus(value: unknown, path: string): TcbStatus {
  if (typeof value === 'string' && TCB_STATUSES.includes(value as TcbStatus)) {
    return value as TcbStatus;
  }
  throw invalidQuoteResult(path, 'known TDX TCB status', value);
}

function requireStringArray(value: unknown, path: string): string[] {
  if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
    return [...value];
  }
  throw invalidQuoteResult(path, 'array of strings', value);
}

function requireBoolean(value: unknown, path: string): boolean {
  if (typeof value === 'boolean') {
    return value;
  }
  throw invalidQuoteResult(path, 'boolean', value);
}

function requireBytes(value: unknown, path: string): Buffer {
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  throw invalidQuoteResult(path, 'Uint8Array', value);
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

function invalidQuoteResult(
  path: string,
  expected: string,
  value: unknown,
): VerificationError {
  return new VerificationError({
    phase: 'quote',
    code: 'quote.invalid_result',
    details: { path, expected, actual: describeValue(value) },
  });
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
