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
  optionalInputObject,
  requireInputObject,
  requireInputString,
} from '../utils/input';
import { normalizeVerifiedTdxQuote, verifyDcapQuote } from '../utils/intel';
import {
  extractImageDigests,
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

/** Validate the parsed SDK evidence before it reaches measurement logic. */
export function requireAttestationEvidence(
  value: unknown,
): AttestationEvidence {
  const attestation = requireInputObject(value, 'attestation');
  const signer = requireInputObject(attestation.signer, 'attestation.signer');
  requireInputString(attestation.nonce, 'attestation.nonce');
  requireInputString(attestation.intelQuote, 'attestation.intelQuote');
  requireInputString(attestation.appCompose, 'attestation.appCompose');
  requireInputString(signer.algorithm, 'attestation.signer.algorithm');
  requireInputString(signer.address, 'attestation.signer.address');

  if (
    typeof attestation.eventLog !== 'string' &&
    !Array.isArray(attestation.eventLog)
  ) {
    throw inputError(
      'attestation.eventLog',
      attestation.eventLog === undefined ? 'missing' : 'unsupported_value',
      { expected: 'JSON string or array' },
    );
  }
  if (
    attestation.declaredSpkiFingerprint !== undefined &&
    attestation.declaredSpkiFingerprint !== null &&
    typeof attestation.declaredSpkiFingerprint !== 'string'
  ) {
    throw inputError(
      'attestation.declaredSpkiFingerprint',
      'unsupported_value',
      { expected: 'string or null' },
    );
  }
  if (
    attestation.reportedQuoteData !== undefined &&
    typeof attestation.reportedQuoteData !== 'string'
  ) {
    throw inputError('attestation.reportedQuoteData', 'unsupported_value', {
      expected: 'string',
    });
  }

  return value as AttestationEvidence;
}

/** Validate policy once at the public boundary before quote verification runs. */
export function parseAttestationPolicy(
  value: unknown,
): AttestationPolicy | undefined {
  const policy = optionalInputObject(value, 'policy');
  if (!policy) {
    return undefined;
  }
  const statuses = policy.acceptedTcbStatuses;
  if (
    statuses !== undefined &&
    (!Array.isArray(statuses) ||
      !statuses.every(
        (status): status is TcbStatus =>
          typeof status === 'string' &&
          TCB_STATUSES.includes(status as TcbStatus),
      ))
  ) {
    throw inputError('policy.acceptedTcbStatuses', 'unsupported_value', {
      expected: 'an array of known TDX TCB statuses',
    });
  }
  return policy as AttestationPolicy;
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
    imageDigests: extractImageDigests(appCompose),
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
    imageDigests: [...deployment.imageDigests],
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
