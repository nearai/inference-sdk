import type { AttestationEvidence } from '../types/attestation-common';
import type {
  AttestationPolicy,
  MeasuredDeployment,
  TdxQuoteVerifier,
  TcbStatus,
  VerifiedTdxQuote,
} from '../types/verification';
import { decodeTdxQuoteVerifierOutput } from '../boundaries/quote-verifier';
import { requireByteLength } from '../utils/common';
import { VerificationError, wrapVerificationError } from '../utils/errors';
import { verifyDcapQuote } from '../utils/intel';
import {
  verifyAdvertisedReportData,
  verifyAppComposeMrConfigBinding,
  verifyReportedNonce,
} from './attestation-common';
import { verifyAndReplayRtmr3 } from './event-log';
import type { QuoteVerificationOptions } from '../types/verification-context';

const DEFAULT_ACCEPTED_TCB_STATUSES: readonly TcbStatus[] = [
  'UpToDate',
  'OutOfDate',
  'TDRelaunchAdvised',
];

/** Quote facts shared by model and gateway evidence. Internal to the SDK. */
export type VerifiedDstackQuote = {
  attestation: AttestationEvidence;
  quote: VerifiedTdxQuote;
  signer: AttestationEvidence['signer'];
};

type VerifyDstackQuoteParams = QuoteVerificationOptions & {
  attestation: AttestationEvidence;
  nonce: string;
  policy?: AttestationPolicy;
  tdxQuoteVerifier?: TdxQuoteVerifier;
  advertisedReportData?: string;
};

/**
 * Authenticate shared dstack quote facts before an endpoint-specific report
 * data binding is checked. Model and gateway callers deliberately apply their
 * own binding rules afterwards; neither path controls the other with flags.
 */
export async function verifyDstackQuote({
  attestation,
  nonce,
  policy,
  tdxQuoteVerifier,
  advertisedReportData,
  context,
  signal,
}: VerifyDstackQuoteParams): Promise<VerifiedDstackQuote> {
  verifyReportedNonce({
    reportedNonce: attestation.nonce,
    nonce,
  });
  const signer = verifySigningAddressLength(
    attestation.signer.signingAlgo,
    attestation.signer.signingAddress,
  );

  const quote = await verifyTdxQuote({
    intelQuote: attestation.intelQuote,
    policy,
    verifier: tdxQuoteVerifier,
    context,
    signal,
  });
  verifyAdvertisedReportData(advertisedReportData, quote.reportData);
  return { attestation, quote, signer };
}

type VerifyTdxQuoteParams = QuoteVerificationOptions & {
  intelQuote: string;
  policy?: AttestationPolicy;
  verifier?: TdxQuoteVerifier;
};

/** Shared CPU trust and TCB policy, independent of the report-data layout. */
export async function verifyTdxQuote({
  intelQuote,
  policy,
  verifier,
  context,
  signal,
}: VerifyTdxQuoteParams): Promise<VerifiedTdxQuote> {
  const acceptedTcbStatuses = getAcceptedTcbStatuses(policy);
  const quote = await verifyQuote(verifier, intelQuote, { context, signal });
  if (quote.debugEnabled) {
    throw new VerificationError({
      code: 'policy.debug_enabled',
    });
  }
  if (!acceptedTcbStatuses.includes(quote.tcbStatus)) {
    throw new VerificationError({
      code: 'policy.tcb_status_not_allowed',
      details: {
        actual: quote.tcbStatus,
        accepted: [...acceptedTcbStatuses],
        advisoryIds: [...quote.advisoryIds],
      },
    });
  }

  return quote;
}

/** Verify the compose binding and replay dstack runtime measurements. */
export async function verifyDstackDeployment(
  verifiedQuote: VerifiedDstackQuote,
): Promise<MeasuredDeployment> {
  const { attestation, quote } = verifiedQuote;
  const runtimeMeasurements = await verifyAndReplayRtmr3(
    attestation.eventLog,
    quote.rtMr3,
  );
  const { appCompose } = attestation;
  await verifyAppComposeMrConfigBinding(appCompose, quote.mrConfigId);
  return {
    appCompose,
    runtimeMeasurements,
  };
}

async function verifyQuote(
  verifier: TdxQuoteVerifier | undefined,
  intelQuote: string,
  options: QuoteVerificationOptions,
): Promise<VerifiedTdxQuote> {
  if (verifier === undefined) {
    return verifyDcapQuote(intelQuote, undefined, options);
  }

  let quote: unknown;
  try {
    quote = await verifier(intelQuote, options);
  } catch (cause) {
    options.signal?.throwIfAborted();
    throw wrapVerificationError(
      {
        code: 'quote.verification_failed',
        details: { reason: 'verifier_error' },
      },
      cause,
    );
  }

  return decodeTdxQuoteVerifierOutput(quote);
}

function getAcceptedTcbStatuses(
  policy: AttestationPolicy | undefined,
): readonly TcbStatus[] {
  const value = policy?.acceptedTcbStatuses;
  if (value === undefined) {
    return DEFAULT_ACCEPTED_TCB_STATUSES;
  }
  return value;
}

function verifySigningAddressLength(
  signingAlgo: AttestationEvidence['signer']['signingAlgo'],
  signingAddress: string,
): VerifiedDstackQuote['signer'] {
  requireByteLength({
    value: signingAddress,
    byteLength: signingAlgo === 'ecdsa' ? 20 : 32,
    label: 'attestation.signer.signingAddress',
  });
  return {
    signingAlgo,
    signingAddress,
  };
}
