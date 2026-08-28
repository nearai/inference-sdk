import type { AttestationEvidence } from '../types/attestation-common';
import type {
  AttestationPolicy,
  DeploymentProvenanceStatus,
  DeploymentVerifier,
  MeasuredDeployment,
  QuoteVerifier,
  TcbStatus,
  VerifiedAttestationEvidence,
  VerifiedTdxQuote,
} from '../types/verification';
import { decodeQuoteVerifierOutput } from '../boundaries/quote-verifier';
import { requireByteLength } from '../utils/common';
import { VerificationError, wrapVerificationError } from '../utils/errors';
import { verifyDcapQuote } from '../utils/intel';
import {
  verifyAdvertisedReportData,
  verifyAppComposeMrConfigBinding,
  verifyReportedNonce,
} from './attestation-common';
import { verifyAndReplayRtmr3 } from './event-log';

const DEFAULT_ACCEPTED_TCB_STATUSES: readonly TcbStatus[] = [
  'UpToDate',
  'OutOfDate',
];

/** Quote facts shared by model and gateway evidence. Internal to the SDK. */
export type VerifiedDstackQuote = {
  attestation: AttestationEvidence;
  quote: VerifiedTdxQuote;
  signer: AttestationEvidence['signer'];
};

type VerifyDstackQuoteParams = {
  attestation: AttestationEvidence;
  nonce: string;
  policy?: AttestationPolicy;
  quoteVerifier?: QuoteVerifier;
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
  quoteVerifier,
  advertisedReportData,
}: VerifyDstackQuoteParams): Promise<VerifiedDstackQuote> {
  const acceptedTcbStatuses = getAcceptedTcbStatuses(policy);

  verifyReportedNonce({
    reportedNonce: attestation.nonce,
    nonce,
  });
  const signer = verifySigningAddressLength(
    attestation.signer.signingAlgo,
    attestation.signer.signingAddress,
  );

  const quote = await verifyQuote(quoteVerifier, attestation.intelQuote);
  verifyAdvertisedReportData(advertisedReportData, quote.reportData);
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
        accepted: acceptedTcbStatuses,
        advisoryIds: quote.advisoryIds,
      },
    });
  }

  return { attestation, quote, signer };
}

/**
 * Replay measurements and optionally apply caller-owned deployment policy.
 * A supplied verifier is required to resolve successfully; there is no second
 * boolean that can silently change that requirement.
 */
export async function verifyDstackDeployment(
  verifiedQuote: VerifiedDstackQuote,
  deploymentVerifier?: DeploymentVerifier,
): Promise<VerifiedAttestationEvidence> {
  const { attestation, quote, signer } = verifiedQuote;
  const runtimeMeasurements = await verifyAndReplayRtmr3(
    attestation.eventLog,
    quote.rtMr3,
  );
  const { appCompose } = attestation;
  await verifyAppComposeMrConfigBinding(appCompose, quote.mrConfigId);
  const deployment: MeasuredDeployment = {
    appCompose,
    runtimeMeasurements,
  };

  let deploymentProvenance: DeploymentProvenanceStatus = 'not_checked';
  if (deploymentVerifier) {
    try {
      await deploymentVerifier(deployment);
      deploymentProvenance = 'verified';
    } catch (cause) {
      throw wrapVerificationError(
        {
          code: 'provenance.verification_failed',
        },
        cause,
      );
    }
  }

  return {
    signer,
    tcbStatus: quote.tcbStatus,
    advisoryIds: quote.advisoryIds,
    deployment,
    deploymentProvenance,
  };
}

async function verifyQuote(
  verifier: QuoteVerifier | undefined,
  intelQuote: string,
): Promise<VerifiedTdxQuote> {
  if (verifier === undefined) {
    return verifyDcapQuote(intelQuote);
  }

  let quote: unknown;
  try {
    quote = await verifier(intelQuote);
  } catch (cause) {
    throw wrapVerificationError(
      {
        code: 'quote.verification_failed',
        details: { reason: 'verifier_error' },
      },
      cause,
    );
  }

  return decodeQuoteVerifierOutput(quote);
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
