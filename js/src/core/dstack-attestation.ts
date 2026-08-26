import type {
  AttestationEventLog,
  AttestationEvidence,
} from '../types/attestation-common';
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
import {
  AttestationEvidenceBaseSchema,
  AttestationPolicyBaseSchema,
} from '../schemas';
import { requireByteLength } from '../utils/common';
import { VerificationError, wrapVerificationError } from '../utils/errors';
import { inputError } from '../utils/input';
import { parsePublicInput } from '../utils/schema';
import { normalizeVerifiedTdxQuote, verifyDcapQuote } from '../utils/intel';
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

/** Validate the parsed SDK evidence before it reaches measurement logic. */
export function requireAttestationEvidence(
  value: unknown,
): AttestationEvidence {
  const attestation = parsePublicInput(
    AttestationEvidenceBaseSchema,
    value,
    'attestation',
  );
  const eventLog = snapshotEventLog(attestation.eventLog);

  return Object.freeze({
    nonce: attestation.nonce,
    signer: Object.freeze({
      algorithm: attestation.signer.algorithm,
      address: attestation.signer.address,
    }),
    intelQuote: attestation.intelQuote,
    eventLog,
    appCompose: attestation.appCompose,
    ...(attestation.declaredSpkiFingerprint !== undefined
      ? { declaredSpkiFingerprint: attestation.declaredSpkiFingerprint }
      : {}),
    ...(attestation.reportedQuoteData !== undefined
      ? { reportedQuoteData: attestation.reportedQuoteData }
      : {}),
  });
}

/**
 * Capture array-form evidence before any asynchronous verification begins.
 * Event-log entries are JSON data, so normalizing an array to JSON preserves
 * the accepted wire representation while preventing later caller mutation.
 */
function snapshotEventLog(eventLog: AttestationEventLog): string {
  if (typeof eventLog === 'string') {
    return eventLog;
  }
  try {
    const serialized = JSON.stringify(eventLog);
    if (typeof serialized === 'string') {
      return serialized;
    }
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'input',
        code: 'input.invalid',
        details: {
          field: 'attestation.eventLog',
          reason: 'unsupported_value',
          expected: 'a JSON-serializable array',
        },
      },
      { cause },
    );
  }
  throw inputError('attestation.eventLog', 'unsupported_value', {
    expected: 'a JSON-serializable array',
  });
}

/** Validate policy once at the public boundary before quote verification runs. */
export function parseAttestationPolicy(
  value: unknown,
): AttestationPolicy | undefined {
  if (value === undefined) {
    return undefined;
  }
  return parsePublicInput(AttestationPolicyBaseSchema, value, 'policy');
}

/**
 * Authenticate shared dstack quote facts before an endpoint-specific report
 * data binding is checked. Model and gateway callers deliberately apply their
 * own binding rules afterwards; neither path controls the other with flags.
 */
export async function verifyDstackQuote(input: {
  attestation: AttestationEvidence;
  nonce: string;
  policy?: AttestationPolicy;
  quoteVerifier?: QuoteVerifier;
  advertisedReportData?: string;
}): Promise<VerifiedDstackQuote> {
  const attestation = requireAttestationEvidence(input.attestation);
  const acceptedTcbStatuses = getAcceptedTcbStatuses(input.policy);

  verifyReportedNonce(attestation.nonce, input.nonce);
  const signer = verifySigningAddressLength(
    attestation.signer.algorithm,
    attestation.signer.address,
  );

  const quote = await verifyQuote(
    input.quoteVerifier ?? verifyDcapQuote,
    attestation.intelQuote,
  );
  verifyAdvertisedReportData(input.advertisedReportData, quote.reportData);
  if (quote.debugEnabled) {
    throw new VerificationError({
      phase: 'policy',
      code: 'policy.debug_enabled',
    });
  }
  if (!acceptedTcbStatuses.includes(quote.tcbStatus)) {
    throw new VerificationError({
      phase: 'policy',
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
      await deploymentVerifier(copyMeasuredDeployment(deployment));
      deploymentProvenance = 'verified';
    } catch (cause) {
      throw wrapVerificationError(
        {
          phase: 'provenance',
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

function copyMeasuredDeployment(
  deployment: MeasuredDeployment,
): MeasuredDeployment {
  return {
    appCompose: deployment.appCompose,
    runtimeMeasurements: { ...deployment.runtimeMeasurements },
  };
}

async function verifyQuote(
  verifier: QuoteVerifier,
  intelQuote: string,
): Promise<VerifiedTdxQuote> {
  let quote: unknown;
  try {
    quote = await verifier(intelQuote);
  } catch (cause) {
    throw wrapVerificationError(
      {
        phase: 'quote',
        code: 'quote.verification_failed',
        details: { reason: 'verifier_error' },
      },
      cause,
    );
  }

  return normalizeVerifiedTdxQuote(quote);
}

function getAcceptedTcbStatuses(
  policy: AttestationPolicy | undefined,
): readonly TcbStatus[] {
  const value = parseAttestationPolicy(policy)?.acceptedTcbStatuses;
  if (value === undefined) {
    return DEFAULT_ACCEPTED_TCB_STATUSES;
  }
  return value;
}

function verifySigningAddressLength(
  signingAlgorithm: AttestationEvidence['signer']['algorithm'],
  signingAddress: string,
): VerifiedDstackQuote['signer'] {
  if (signingAlgorithm !== 'ecdsa' && signingAlgorithm !== 'ed25519') {
    throw new VerificationError({
      phase: 'input',
      code: 'input.invalid',
      details: {
        field: 'attestation.signer.algorithm',
        reason: 'unsupported_value',
        expected: "'ecdsa' or 'ed25519'",
      },
    });
  }
  requireByteLength(
    signingAddress,
    signingAlgorithm === 'ecdsa' ? 20 : 32,
    'attestation.signer.address',
  );
  return { algorithm: signingAlgorithm, address: signingAddress };
}
