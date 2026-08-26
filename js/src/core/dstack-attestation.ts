import type { DstackAttestation } from '../types/attestation-common';
import type {
  GpuVerifier,
  NearVerificationPolicy,
  ProvenanceVerifier,
  QuoteVerifier,
  ReportDataBinding,
  VerifiedDstackAttestation,
  VerifiedTdxQuote,
} from '../types/verification';
import { requireByteLength } from '../utils/common';
import { VerificationError, wrapVerificationError } from '../utils/errors';
import { normalizeVerifiedTdxQuote, verifyDcapQuote } from '../utils/intel';
import { nvidiaNrasVerifier } from '../utils/nvidia';
import {
  extractImageDigests,
  getRawAppCompose,
  verifyAdvertisedReportData,
  verifyAppComposeMrConfigBinding,
  verifyReportedNonce,
} from './attestation-common';
import { verifyAndReplayRtmr3 } from './event-log';

const DEFAULT_POLICY: Required<NearVerificationPolicy> = {
  allowedTcbStatuses: ['UpToDate', 'OutOfDate'],
  requireGpuEvidence: false,
  requireDeploymentProvenance: false,
};

export type VerifyDstackAttestationInput<
  TReportDataBinding extends ReportDataBinding,
> = {
  target: 'near_model' | 'gateway';
  attestation: DstackAttestation;
  expectedNonce: string;
  quoteVerifier?: QuoteVerifier;
  gpuVerifier?: GpuVerifier;
  provenanceVerifier?: ProvenanceVerifier;
  policy?: NearVerificationPolicy;
  nvidiaPayload?: string | null;
  verifyGpu: boolean;
  advertisedReportData?: string;
  verifyReportDataBinding(reportData: Uint8Array): Promise<TReportDataBinding>;
};

/**
 * Shared quote/measurement orchestration. Endpoint-specific callers supply
 * the report-data binding rule: Cloud model evidence and gateway TLS evidence
 * intentionally have different trust boundaries. The quote is authenticated
 * before its report data, measurements, and caller policy are evaluated.
 */
export async function verifyDstackAttestation<
  TReportDataBinding extends ReportDataBinding,
>(
  input: VerifyDstackAttestationInput<TReportDataBinding>,
): Promise<VerifiedDstackAttestation<TReportDataBinding>> {
  const policy = { ...DEFAULT_POLICY, ...input.policy };
  const { attestation } = input;

  verifyReportedNonce(attestation.request_nonce, input.expectedNonce);
  verifySigningAddressLength(
    attestation.signing_algo,
    attestation.signing_address,
  );

  const quote = await verifyQuote(
    input.quoteVerifier ?? { verify: verifyDcapQuote },
    attestation.intel_quote,
  );
  verifyAdvertisedReportData(input.advertisedReportData, quote.reportData);
  if (quote.debugEnabled) {
    throw new VerificationError({
      phase: 'policy',
      code: 'policy.debug_enabled',
      details: { target: input.target },
    });
  }
  if (!policy.allowedTcbStatuses.includes(quote.tcbStatus)) {
    throw new VerificationError({
      phase: 'policy',
      code: 'policy.tcb_status_not_allowed',
      details: {
        target: input.target,
        actual: quote.tcbStatus,
        allowed: policy.allowedTcbStatuses,
        advisoryIds: quote.advisoryIds,
      },
    });
  }

  const reportDataBinding = await input.verifyReportDataBinding(
    quote.reportData,
  );
  const runtimeMeasurements = await verifyAndReplayRtmr3(
    attestation.event_log,
    quote.rtMr3,
  );
  const appCompose = getRawAppCompose(attestation.info.tcb_info);
  await verifyAppComposeMrConfigBinding(appCompose, quote.mrConfigId);
  const imageDigests = extractImageDigests(appCompose);

  if (policy.requireDeploymentProvenance && !input.provenanceVerifier) {
    throw new VerificationError({
      phase: 'policy',
      code: 'policy.provenance_verifier_required',
      details: {},
    });
  }

  const provenanceVerified = Boolean(input.provenanceVerifier);
  if (input.provenanceVerifier) {
    try {
      await input.provenanceVerifier.verify({
        appCompose,
        imageDigests,
        runtimeMeasurements,
      });
    } catch (cause) {
      throw wrapVerificationError(
        {
          phase: 'provenance',
          code: 'provenance.verification_failed',
          details: {},
        },
        cause,
      );
    }
  }

  const gpuVerified = input.verifyGpu
    ? await verifyGpuEvidence(
        input.nvidiaPayload,
        input.expectedNonce,
        policy.requireGpuEvidence,
        input.gpuVerifier ?? nvidiaNrasVerifier,
      )
    : undefined;

  return {
    signingAddress: attestation.signing_address,
    signingAlgo: attestation.signing_algo,
    reportDataBinding,
    tcbStatus: quote.tcbStatus,
    advisoryIds: quote.advisoryIds,
    appCompose,
    imageDigests,
    runtimeMeasurements,
    provenanceVerified,
    ...(gpuVerified ? { gpuVerified } : {}),
  };
}

async function verifyGpuEvidence(
  payload: string | null | undefined,
  expectedNonce: string,
  requireGpuEvidence: boolean,
  verifier: GpuVerifier,
): Promise<true | undefined> {
  if (payload === undefined || payload === null || payload === '') {
    if (requireGpuEvidence) {
      throw new VerificationError({
        phase: 'policy',
        code: 'policy.gpu_evidence_required',
        details: {},
      });
    }
    return undefined;
  }

  // Bind the provider payload to the same nonce before handing it to either
  // the default NRAS verifier or a caller-supplied GPU trust implementation.
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'gpu',
        code: 'gpu.payload_invalid',
        details: { reason: 'invalid_json' },
      },
      { cause },
    );
  }
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    typeof (parsed as Record<string, unknown>).nonce !== 'string'
  ) {
    throw new VerificationError({
      phase: 'gpu',
      code: 'gpu.payload_invalid',
      details: { reason: 'nonce_missing' },
    });
  }
  const payloadNonce = (parsed as Record<string, string>).nonce;
  verifyReportedNonce(payloadNonce, expectedNonce, 'nvidia_payload');

  try {
    await verifier.verify(payload);
  } catch (cause) {
    throw wrapVerificationError(
      {
        phase: 'gpu',
        code: 'gpu.attestation_rejected',
        details: { source: 'custom_verifier' },
      },
      cause,
    );
  }
  return true;
}

async function verifyQuote(
  verifier: QuoteVerifier,
  intelQuote: string,
): Promise<VerifiedTdxQuote> {
  let quote: unknown;
  try {
    quote = await verifier.verify(intelQuote);
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

function verifySigningAddressLength(
  signingAlgo: DstackAttestation['signing_algo'],
  signingAddress: string,
): void {
  if (signingAlgo !== 'ecdsa' && signingAlgo !== 'ed25519') {
    throw new VerificationError({
      phase: 'input',
      code: 'input.invalid',
      details: {
        field: 'signing_algo',
        reason: 'unsupported_value',
        expected: "'ecdsa' or 'ed25519'",
      },
    });
  }
  requireByteLength(
    signingAddress,
    signingAlgo === 'ecdsa' ? 20 : 32,
    'signing_address',
  );
}
