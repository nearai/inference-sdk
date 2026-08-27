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
import { requireByteLength } from '../utils/common';
import { VerificationError, wrapVerificationError } from '../utils/errors';
import {
  inputError,
  optionalInputString,
  rejectUnknownInputKeys,
  requireInputArray,
  requireInputObject,
  requireInputString,
} from '../utils/input';
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

/** Quote facts shared by model and gateway evidence. Internal to the SDK. */
export type VerifiedDstackQuote = {
  attestation: AttestationEvidence;
  quote: VerifiedTdxQuote;
  signer: AttestationEvidence['signer'];
};

/**
 * Snapshot shared evidence before it reaches asynchronous measurement logic.
 * Endpoint-specific public entry points validate their own complete input
 * shape; this helper intentionally permits their extra evidence fields.
 */
export function requireAttestationEvidence(
  value: unknown,
): AttestationEvidence {
  const attestation = requireInputObject(value, 'attestation');
  const nonce = requireInputString(attestation.nonce, 'attestation.nonce');
  const signer = snapshotSigningIdentity(attestation.signer);
  const intelQuote = requireInputString(
    attestation.intelQuote,
    'attestation.intelQuote',
  );
  const eventLog = snapshotEventLog(attestation.eventLog);
  const appCompose = requireInputString(
    attestation.appCompose,
    'attestation.appCompose',
  );
  const declaredSpkiFingerprint = optionalNullableInputString(
    attestation.declaredSpkiFingerprint,
    'attestation.declaredSpkiFingerprint',
  );
  const reportedQuoteData = optionalInputString(
    attestation.reportedQuoteData,
    'attestation.reportedQuoteData',
  );

  return {
    nonce,
    signer,
    intelQuote,
    eventLog,
    appCompose,
    ...(declaredSpkiFingerprint !== undefined
      ? { declaredSpkiFingerprint }
      : {}),
    ...(reportedQuoteData !== undefined ? { reportedQuoteData } : {}),
  };
}

/**
 * Capture array-form evidence before any asynchronous verification begins.
 * Event-log entries are JSON data, so normalizing an array to JSON preserves
 * the accepted wire representation while preventing later caller mutation.
 */
function snapshotEventLog(eventLog: unknown): string {
  if (typeof eventLog === 'string') {
    return eventLog;
  }
  const eventLogArray = requireInputArray(eventLog, 'attestation.eventLog');
  try {
    const serialized = JSON.stringify(eventLogArray);
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

/** Snapshot shared policy fields before quote verification runs. */
export function parseAttestationPolicy(
  value: unknown,
): AttestationPolicy | undefined {
  if (value === undefined) {
    return undefined;
  }
  const policy = requireInputObject(value, 'policy');
  const acceptedTcbStatuses = parseAcceptedTcbStatuses(
    policy.acceptedTcbStatuses,
  );
  return {
    ...(acceptedTcbStatuses !== undefined ? { acceptedTcbStatuses } : {}),
  };
}

/** Validate and snapshot the shared TCB-status policy field. */
export function parseAcceptedTcbStatuses(
  value: unknown,
): readonly TcbStatus[] | undefined {
  if (value === undefined) {
    return undefined;
  }

  const values = requireInputArray(value, 'policy.acceptedTcbStatuses');
  const acceptedTcbStatuses: TcbStatus[] = [];
  for (let index = 0; index < values.length; index += 1) {
    acceptedTcbStatuses.push(
      requireTcbStatus(values[index], `policy.acceptedTcbStatuses.${index}`),
    );
  }
  return acceptedTcbStatuses;
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
  const policy = parseAttestationPolicy(input.policy);
  const acceptedTcbStatuses = getAcceptedTcbStatuses(policy);
  const quoteVerifier = input.quoteVerifier ?? verifyDcapQuote;
  const advertisedReportData = input.advertisedReportData;

  verifyReportedNonce(attestation.nonce, input.nonce);
  const signer = verifySigningAddressLength(
    attestation.signer.signingAlgo,
    attestation.signer.signingAddress,
  );

  const quote = await verifyQuote(quoteVerifier, attestation.intelQuote);
  verifyAdvertisedReportData(advertisedReportData, quote.reportData);
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
  const value = policy?.acceptedTcbStatuses;
  if (value === undefined) {
    // Use a fresh default-policy snapshot for every verification. The
    // accepted statuses are included in a public error on policy failure, so
    // returning the module-level array here would let a caller mutate a later
    // verification's default policy through a caught error.
    return [...DEFAULT_ACCEPTED_TCB_STATUSES];
  }
  return value;
}

function snapshotSigningIdentity(
  value: unknown,
): AttestationEvidence['signer'] {
  const signer = requireInputObject(value, 'attestation.signer');
  rejectUnknownInputKeys(signer, 'attestation.signer', [
    'signingAlgo',
    'signingAddress',
  ]);
  const signingAlgo = requireSigningAlgo(
    signer.signingAlgo,
    'attestation.signer.signingAlgo',
  );
  const signingAddress = requireInputString(
    signer.signingAddress,
    'attestation.signer.signingAddress',
  );

  return { signingAlgo, signingAddress };
}

function optionalNullableInputString(
  value: unknown,
  field: string,
): string | null | undefined {
  if (value === undefined || value === null) {
    return value;
  }
  return requireInputString(value, field);
}

function requireTcbStatus(value: unknown, field: string): TcbStatus {
  if (isTcbStatus(value)) {
    return value;
  }
  throw inputError(
    field,
    value === undefined ? 'missing' : 'unsupported_value',
    { expected: 'a supported TCB status' },
  );
}

function isTcbStatus(value: unknown): value is TcbStatus {
  return (
    typeof value === 'string' && TCB_STATUSES.some((status) => status === value)
  );
}

function requireSigningAlgo(
  value: unknown,
  field: string,
): AttestationEvidence['signer']['signingAlgo'] {
  if (value === 'ecdsa' || value === 'ed25519') {
    return value;
  }
  throw inputError(
    field,
    value === undefined ? 'missing' : 'unsupported_value',
    { expected: "'ecdsa' or 'ed25519'" },
  );
}

function verifySigningAddressLength(
  signingAlgo: AttestationEvidence['signer']['signingAlgo'],
  signingAddress: string,
): VerifiedDstackQuote['signer'] {
  if (signingAlgo !== 'ecdsa' && signingAlgo !== 'ed25519') {
    throw new VerificationError({
      phase: 'input',
      code: 'input.invalid',
      details: {
        field: 'attestation.signer.signingAlgo',
        reason: 'unsupported_value',
        expected: "'ecdsa' or 'ed25519'",
      },
    });
  }
  requireByteLength(
    signingAddress,
    signingAlgo === 'ecdsa' ? 20 : 32,
    'attestation.signer.signingAddress',
  );
  return {
    signingAlgo,
    signingAddress,
  };
}
