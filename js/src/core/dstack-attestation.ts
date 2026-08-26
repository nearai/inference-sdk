import { DstackAttestation } from '../types/attestation-common';
import {
  GpuVerifier,
  NearVerificationPolicy,
  ProvenanceVerifier,
  QuoteVerifier,
  TcbStatus,
  VerifiedDstackAttestation,
} from '../types/verification';
import { requireByteLength } from '../utils/common';
import { VerificationError } from '../utils/errors';
import { verifyDcapQuote } from '../utils/intel';
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
  allowedTcbStatuses: [TcbStatus.UpToDate, TcbStatus.OutOfDate],
  requireGpuEvidence: false,
  requireDeploymentProvenance: false,
};

export type VerifyDstackAttestationInput = {
  attestation: DstackAttestation;
  expectedNonce: string;
  quoteVerifier?: QuoteVerifier;
  gpuVerifier?: GpuVerifier;
  provenanceVerifier?: ProvenanceVerifier;
  policy?: NearVerificationPolicy;
  nvidiaPayload?: string | null;
  verifyGpu: boolean;
  advertisedReportData?: string;
  verifyReportDataBinding(reportData: Uint8Array): Promise<string>;
};

/**
 * Shared quote/measurement orchestration. Endpoint-specific callers supply
 * the report-data binding rule: Cloud model evidence and gateway TLS evidence
 * intentionally have different trust boundaries.
 */
export async function verifyDstackAttestation(
  input: VerifyDstackAttestationInput,
): Promise<VerifiedDstackAttestation> {
  const policy = { ...DEFAULT_POLICY, ...input.policy };
  const { attestation } = input;

  verifyReportedNonce(attestation.request_nonce, input.expectedNonce);
  verifySigningAddressLength(
    attestation.signing_algo,
    attestation.signing_address,
  );

  const quote = await (
    input.quoteVerifier ?? { verify: verifyDcapQuote }
  ).verify(attestation.intel_quote);
  verifyAdvertisedReportData(input.advertisedReportData, quote.reportData);
  if (quote.debugEnabled) {
    throw new VerificationError('TDX debug mode is enabled');
  }
  if (!policy.allowedTcbStatuses.includes(quote.tcbStatus)) {
    throw new VerificationError(
      `TDX TCB status '${quote.tcbStatus}' is not allowed by policy`,
    );
  }

  const tlsCertFingerprint = await input.verifyReportDataBinding(
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
    throw new VerificationError(
      'deployment provenance is required by policy but no provenanceVerifier was provided',
    );
  }

  const provenanceVerified = Boolean(input.provenanceVerifier);
  if (input.provenanceVerifier) {
    await input.provenanceVerifier.verify({
      appCompose,
      imageDigests,
      runtimeMeasurements,
    });
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
    tlsCertFingerprint,
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
  required: boolean,
  verifier: GpuVerifier,
): Promise<true | undefined> {
  if (payload === undefined || payload === null || payload === '') {
    if (required) {
      throw new VerificationError(
        'GPU evidence is required by policy but absent',
      );
    }
    return undefined;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch (cause) {
    throw new VerificationError('nvidia_payload is not valid JSON', cause);
  }
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    typeof (parsed as Record<string, unknown>).nonce !== 'string'
  ) {
    throw new VerificationError('nvidia_payload is missing its nonce');
  }
  const payloadNonce = (parsed as Record<string, string>).nonce;
  verifyReportedNonce(payloadNonce, expectedNonce);

  await verifier.verify(payload);
  return true;
}

function verifySigningAddressLength(
  signingAlgo: DstackAttestation['signing_algo'],
  signingAddress: string,
): void {
  requireByteLength(
    signingAddress,
    signingAlgo === 'ecdsa' ? 20 : 32,
    'signing_address',
  );
}
