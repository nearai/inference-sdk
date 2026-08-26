import type {
  GpuEvidenceStatus,
  ModelAttestationPolicy,
  NvidiaEvidenceVerifier,
  VerifiedModelAttestation,
  VerifyModelAttestationInput,
} from '../types/verification';
import { VerificationError, wrapVerificationError } from '../utils/errors';
import {
  inputError,
  optionalInputObject,
  rejectUnknownInputKeys,
  requireInputFunction,
  requireInputObject,
  requireInputString,
} from '../utils/input';
import { nvidiaNrasVerifier } from '../utils/nvidia';
import {
  verifyCloudModelReportDataBinding,
  verifyReportedNonce,
} from './attestation-common';
import {
  verifyDstackDeployment,
  verifyDstackQuote,
  parseAttestationPolicy,
  requireAttestationEvidence,
} from './dstack-attestation';
import { markVerifiedModelAttestation } from './verified-attestation';

/**
 * Verify model evidence returned through NEAR AI Cloud. This verifies freshness
 * and the model signing identity but does not claim a client-to-model TLS
 * binding; the client's TLS connection terminates at the gateway.
 */
export async function verifyModelAttestation(
  input: VerifyModelAttestationInput,
): Promise<VerifiedModelAttestation> {
  const parsed = parseModelAttestationInput(input);
  const { attestation, nonce, policy, verifiers } = parsed;
  const verifiedQuote = await verifyDstackQuote({
    attestation,
    nonce,
    policy,
    quoteVerifier: verifiers?.quote,
    advertisedReportData: attestation.reportedQuoteData,
  });
  const tlsBinding = await verifyCloudModelReportDataBinding({
    reportData: verifiedQuote.quote.reportData,
    nonce,
    signingAddress: attestation.signer.address,
    reportedSpkiFingerprint: attestation.declaredSpkiFingerprint,
  });
  const evidence = await verifyDstackDeployment(
    verifiedQuote,
    verifiers?.deployment,
  );
  const gpuEvidence = await verifyNvidiaEvidence({
    payload: attestation.nvidiaPayload,
    nonce,
    requirement: getGpuEvidenceRequirement(policy),
    verifier: verifiers?.nvidia ?? nvidiaNrasVerifier,
  });

  return markVerifiedModelAttestation({ ...evidence, tlsBinding, gpuEvidence });
}

function parseModelAttestationInput(input: unknown): {
  attestation: VerifyModelAttestationInput['attestation'];
  nonce: string;
  policy: ModelAttestationPolicy | undefined;
  verifiers: VerifyModelAttestationInput['verifiers'];
} {
  const record = requireInputObject(input, 'input');
  rejectUnknownInputKeys(record, 'input', [
    'attestation',
    'nonce',
    'policy',
    'verifiers',
  ]);
  const attestation = requireAttestationEvidence(
    record.attestation,
  ) as VerifyModelAttestationInput['attestation'];
  if (
    attestation.nvidiaPayload !== undefined &&
    attestation.nvidiaPayload !== null &&
    typeof attestation.nvidiaPayload !== 'string'
  ) {
    throw inputError('attestation.nvidiaPayload', 'unsupported_value', {
      expected: 'string or null',
    });
  }
  return {
    attestation,
    nonce: requireInputString(record.nonce, 'nonce'),
    policy: parseModelAttestationPolicy(record.policy),
    verifiers: parseModelAttestationVerifiers(record.verifiers),
  };
}

function parseModelAttestationPolicy(
  value: unknown,
): ModelAttestationPolicy | undefined {
  const policy = optionalInputObject(value, 'policy');
  if (!policy) {
    return undefined;
  }
  rejectUnknownInputKeys(policy, 'policy', [
    'acceptedTcbStatuses',
    'gpuEvidence',
  ]);
  parseAttestationPolicy(policy);

  const gpuEvidence = policy.gpuEvidence;
  if (
    gpuEvidence !== undefined &&
    gpuEvidence !== 'if-present' &&
    gpuEvidence !== 'required'
  ) {
    throw inputError('policy.gpuEvidence', 'unsupported_value', {
      expected: "'if-present' or 'required'",
    });
  }
  return policy as ModelAttestationPolicy;
}

function parseModelAttestationVerifiers(
  value: unknown,
): VerifyModelAttestationInput['verifiers'] {
  const verifiers = optionalInputObject(value, 'verifiers');
  if (!verifiers) {
    return undefined;
  }
  rejectUnknownInputKeys(verifiers, 'verifiers', [
    'quote',
    'deployment',
    'nvidia',
  ]);
  if (verifiers.quote !== undefined) {
    requireInputFunction(verifiers.quote, 'verifiers.quote');
  }
  if (verifiers.deployment !== undefined) {
    requireInputFunction(verifiers.deployment, 'verifiers.deployment');
  }
  if (verifiers.nvidia !== undefined) {
    requireInputFunction(verifiers.nvidia, 'verifiers.nvidia');
  }
  return verifiers as VerifyModelAttestationInput['verifiers'];
}

async function verifyNvidiaEvidence(input: {
  payload: string | null | undefined;
  nonce: string;
  requirement: 'if-present' | 'required';
  verifier: NvidiaEvidenceVerifier;
}): Promise<GpuEvidenceStatus> {
  if (input.payload === undefined || input.payload === null) {
    if (input.requirement === 'required') {
      throw new VerificationError({
        phase: 'policy',
        code: 'policy.gpu_evidence_required',
      });
    }
    return 'not_provided';
  }

  // Bind the provider payload to the same nonce before handing it to either
  // the default NRAS verifier or a caller-supplied NVIDIA verifier.
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.payload);
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
  verifyReportedNonce(
    (parsed as Record<string, string>).nonce,
    input.nonce,
    'nvidiaPayload',
  );

  try {
    await input.verifier(input.payload);
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
  return 'verified';
}

function getGpuEvidenceRequirement(
  policy: ModelAttestationPolicy | undefined,
): 'if-present' | 'required' {
  const requirement = policy?.gpuEvidence;
  if (requirement === undefined) {
    return 'if-present';
  }
  if (requirement === 'if-present' || requirement === 'required') {
    return requirement;
  }
  throw new VerificationError({
    phase: 'input',
    code: 'input.invalid',
    details: {
      field: 'policy.gpuEvidence',
      reason: 'unsupported_value',
      expected: "'if-present' or 'required'",
    },
  });
}
