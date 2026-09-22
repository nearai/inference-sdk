import 'reflect-metadata';
import { X509Certificate } from '@peculiar/x509';
import { Buffer } from 'buffer';
import type {
  ChutesGpuEvidence,
  ChutesAttestationPolicy,
  ChutesAttestationVerifiers,
  ChutesModelAttestation,
  ChutesMeasuredDeployment,
  ChutesMeasurementBaseline,
  ChutesMeasurements,
  VerifiedChutesModelAttestation,
  VerifyChutesModelAttestationParams,
} from '../types/attestation-chutes';
import type {
  GpuEvidenceVerifier,
  TcbStatus,
  VerifiedTdxQuote,
} from '../types/verification';
import { CHUTES_MEASUREMENT_BASELINES } from '../utils/chutes-measurements';
import { requireByteLength, sha256, utf8 } from '../utils/common';
import {
  inputError,
  VerificationError,
  wrapVerificationError,
} from '../utils/errors';
import { createGpuEvidenceVerifier } from '../utils/nvidia';
import { verifyReportedNonce } from './attestation-common';
import { verifyQuote } from './dstack-attestation';

const REGISTER_NAMES = ['mrTd', 'rtMr0', 'rtMr1', 'rtMr2', 'rtMr3'] as const;
const DEFAULT_ACCEPTED_TCB_STATUSES: readonly TcbStatus[] = ['UpToDate'];

/**
 * Verify Chutes evidence independently of the Gateway's reported verdict.
 *
 * This authenticates the ML-KEM routing key, certificate SPKI, confidential GPU
 * evidence and a vetted VM baseline. It neither verifies a live Chutes TLS peer
 * nor proves a particular model workload or model-generated response signature.
 */
export async function verifyChutesModelAttestation({
  attestation,
  clientBinding,
  policy,
  verifiers,
}: VerifyChutesModelAttestationParams): Promise<VerifiedChutesModelAttestation> {
  const baselines = normalizeBaselines(
    policy?.baselines ?? CHUTES_MEASUREMENT_BASELINES,
  );
  if (baselines.length === 0) {
    throw new VerificationError({
      code: 'measurement.chutes_baseline_mismatch',
    });
  }
  verifyReportedNonce({
    reportedNonce: attestation.nonce,
    nonce: clientBinding.nonce,
  });
  // Chutes hashes the original textual nonce, not its hex-decoded bytes.
  if (attestation.nonce !== clientBinding.nonce) {
    throw new VerificationError({
      code: 'binding.nonce_mismatch',
      details: { source: 'attestationNonce' },
    });
  }
  const publicKeyBytes = decodeBase64(
    attestation.publicKey,
    'attestation.publicKey',
  );
  if (publicKeyBytes.length !== 1184) {
    throw inputError({
      field: 'attestation.publicKey',
      reason: 'wrong_length',
      details: { expectedBytes: 1184, actualBytes: publicKeyBytes.length },
    });
  }
  const challenge = await sha256(
    utf8(clientBinding.nonce + attestation.publicKey),
  );
  const gpuPayload = createNrasPayload(
    attestation.gpuEvidence,
    challenge.toString('hex'),
  );
  const [cpu] = await Promise.all([
    verifyChutesCpu({ attestation, challenge, baselines, policy, verifiers }),
    verifyChutesGpu(gpuPayload, verifiers?.gpuEvidence),
  ]);
  return { ...cpu, gpuEvidence: 'verified' };
}

type VerifyChutesCpuParams = {
  attestation: ChutesModelAttestation;
  challenge: Buffer;
  baselines: readonly ChutesMeasurementBaseline[];
  policy?: ChutesAttestationPolicy;
  verifiers?: ChutesAttestationVerifiers;
};

async function verifyChutesCpu({
  attestation,
  challenge,
  baselines,
  policy,
  verifiers,
}: VerifyChutesCpuParams): Promise<
  Omit<VerifiedChutesModelAttestation, 'gpuEvidence'>
> {
  const spkiFingerprint = await certificateSpkiFingerprint(
    attestation.certificate,
  );
  const quote = await verifyQuote(verifiers?.tdxQuote, attestation.intelQuote);
  if (quote.reportData.length !== 64) {
    throw new VerificationError({
      code: 'binding.report_data_invalid',
      details: {
        source: 'quoteReportData',
        reason: 'wrong_length',
        expectedBytes: 64,
        actualBytes: quote.reportData.length,
      },
    });
  }
  const acceptedTcbStatuses =
    policy?.acceptedTcbStatuses ?? DEFAULT_ACCEPTED_TCB_STATUSES;
  if (quote.debugEnabled) {
    throw new VerificationError({ code: 'policy.debug_enabled' });
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
  if (!quote.reportData.subarray(0, 32).equals(challenge)) {
    throw new VerificationError({
      code: 'binding.report_data_mismatch',
      details: { source: 'chutesFreshness' },
    });
  }
  if (!quote.reportData.subarray(32, 64).equals(spkiFingerprint)) {
    throw new VerificationError({
      code: 'binding.report_data_mismatch',
      details: { source: 'chutesCertificate' },
    });
  }

  const measurements = quoteMeasurements(quote);
  const matched = baselines.find((baseline) =>
    REGISTER_NAMES.every((name) => baseline[name] === measurements[name]),
  );
  if (!matched) {
    throw new VerificationError({
      code: 'measurement.chutes_baseline_mismatch',
    });
  }
  const deployment: ChutesMeasuredDeployment = {
    ...measurements,
    baseline: { name: matched.name, version: matched.version },
  };
  if (verifiers?.deployment) {
    try {
      await verifiers.deployment(deployment);
    } catch (cause) {
      throw wrapVerificationError(
        { code: 'provenance.verification_failed' },
        cause,
      );
    }
  }
  return {
    provider: 'chutes',
    tcbStatus: quote.tcbStatus,
    advisoryIds: [...quote.advisoryIds],
    publicKey: attestation.publicKey,
    spkiFingerprint: spkiFingerprint.toString('hex'),
    deployment,
    deploymentProvenance: 'verified',
  };
}

async function verifyChutesGpu(
  payload: string,
  verifier: GpuEvidenceVerifier | undefined,
): Promise<void> {
  try {
    await (verifier ?? createGpuEvidenceVerifier())(payload);
  } catch (cause) {
    throw wrapVerificationError(
      {
        code: 'gpu.attestation_rejected',
        details: { source: 'custom_verifier' },
      },
      cause,
    );
  }
}

function normalizeBaselines(
  baselines: readonly ChutesMeasurementBaseline[],
): ChutesMeasurementBaseline[] {
  return baselines.map((baseline, index) => {
    const readRegister = (name: keyof ChutesMeasurements): string =>
      requireByteLength({
        value: baseline[name],
        byteLength: 48,
        label: `policy.baselines[${index}].${name}`,
      }).toString('hex');
    return {
      name: baseline.name,
      version: baseline.version,
      mrTd: readRegister('mrTd'),
      rtMr0: readRegister('rtMr0'),
      rtMr1: readRegister('rtMr1'),
      rtMr2: readRegister('rtMr2'),
      rtMr3: readRegister('rtMr3'),
    };
  });
}

function quoteMeasurements(quote: VerifiedTdxQuote): ChutesMeasurements {
  const readRegister = (name: keyof ChutesMeasurements): string => {
    const value = quote[name];
    if (value === undefined || value.length !== 48) {
      throw new VerificationError({
        code: 'quote.invalid_result',
        details: {
          path: `quote.${name}`,
          expected: '48-byte measurement for Chutes verification',
          actual: value === undefined ? 'undefined' : 'wrong_length',
        },
      });
    }
    return Buffer.from(value).toString('hex');
  };
  return {
    mrTd: readRegister('mrTd'),
    rtMr0: readRegister('rtMr0'),
    rtMr1: readRegister('rtMr1'),
    rtMr2: readRegister('rtMr2'),
    rtMr3: readRegister('rtMr3'),
  };
}

/** Decode canonical standard base64, rather than Buffer's permissive decoder. */
function decodeBase64(value: string, field: string): Buffer {
  const decoded = Buffer.from(value, 'base64');
  if (
    value.length === 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    ) ||
    decoded.toString('base64') !== value
  ) {
    throw inputError({ field, reason: 'invalid_base64' });
  }
  return decoded;
}

async function certificateSpkiFingerprint(
  certificate: string,
): Promise<Buffer> {
  const der = decodeBase64(certificate.trim(), 'attestation.certificate');
  let spki: ArrayBuffer;
  try {
    spki = new X509Certificate(Uint8Array.from(der).buffer).publicKey.rawData;
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'input.invalid',
        details: {
          field: 'attestation.certificate',
          reason: 'invalid_certificate',
        },
      },
      { cause },
    );
  }
  return sha256(new Uint8Array(spki));
}

function createNrasPayload(
  evidence: readonly ChutesGpuEvidence[],
  nonce: string,
): string {
  if (evidence.length === 0) {
    throw new VerificationError({ code: 'policy.gpu_evidence_required' });
  }
  const arch = evidence[0].arch.trim();
  if (arch.length === 0) {
    throw new VerificationError({
      code: 'gpu.payload_invalid',
      details: { reason: 'invalid_schema' },
    });
  }
  if (evidence.some((gpu) => gpu.arch.trim() !== arch)) {
    throw new VerificationError({
      code: 'gpu.payload_invalid',
      details: { reason: 'mixed_architectures' },
    });
  }
  const evidenceList = evidence.map((gpu, index) => {
    const certificate = gpu.certificate.trim();
    const measurement = gpu.evidence.trim();
    decodeBase64(certificate, `attestation.gpuEvidence[${index}].certificate`);
    decodeBase64(measurement, `attestation.gpuEvidence[${index}].evidence`);
    return { certificate, evidence: measurement };
  });
  return JSON.stringify({ nonce, arch, evidence_list: evidenceList });
}
