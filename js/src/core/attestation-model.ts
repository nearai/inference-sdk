import type {
  GpuEvidenceStatus,
  ModelAttestationPolicy,
  ModelAttestationVerifiers,
  NvidiaEvidenceVerifier,
  VerifiedModelAttestation,
  VerifyModelAttestationInput,
} from '../types/verification';
import { VerificationError, wrapVerificationError } from '../utils/errors';
import {
  inputError,
  optionalInputFunction,
  rejectUnknownInputKeys,
  requireInputObject,
  requireInputString,
} from '../utils/input';
import { nvidiaNrasVerifier } from '../utils/nvidia';
import {
  verifyCloudModelReportDataBinding,
  verifyReportedNonce,
} from './attestation-common';
import {
  requireAttestationEvidence,
  parseAcceptedTcbStatuses,
  verifyDstackDeployment,
  verifyDstackQuote,
} from './dstack-attestation';

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
    signingAddress: verifiedQuote.signer.signingAddress,
    reportedSpkiFingerprint: verifiedQuote.attestation.declaredSpkiFingerprint,
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

  return { ...evidence, tlsBinding, gpuEvidence };
}

type ParsedModelAttestationInput = VerifyModelAttestationInput;

function parseModelAttestationInput(
  input: unknown,
): ParsedModelAttestationInput {
  const value = requireInputObject(input, 'input');
  rejectUnknownInputKeys(value, 'input', [
    'attestation',
    'nonce',
    'policy',
    'verifiers',
  ]);

  const attestationInput = requireInputObject(value.attestation, 'attestation');
  rejectUnknownInputKeys(attestationInput, 'attestation', [
    'nonce',
    'signer',
    'intelQuote',
    'eventLog',
    'appCompose',
    'declaredSpkiFingerprint',
    'reportedQuoteData',
    'nvidiaPayload',
  ]);
  const signerInput = requireInputObject(
    attestationInput.signer,
    'attestation.signer',
  );
  rejectUnknownInputKeys(signerInput, 'attestation.signer', [
    'signingAlgo',
    'signingAddress',
  ]);
  const baseAttestation = requireAttestationEvidence(attestationInput);
  const nvidiaPayload = parseNvidiaPayload(attestationInput.nvidiaPayload);

  return {
    attestation: {
      ...baseAttestation,
      ...(nvidiaPayload !== undefined ? { nvidiaPayload } : {}),
    },
    nonce: requireInputString(value.nonce, 'nonce'),
    ...(value.policy !== undefined
      ? { policy: parseModelAttestationPolicy(value.policy) }
      : {}),
    ...(value.verifiers !== undefined
      ? { verifiers: parseModelAttestationVerifiers(value.verifiers) }
      : {}),
  };
}

function parseNvidiaPayload(value: unknown): string | null | undefined {
  if (value === undefined || value === null || typeof value === 'string') {
    return value;
  }
  throw inputError('attestation.nvidiaPayload', 'unsupported_value', {
    expected: 'string or null',
  });
}

function parseModelAttestationPolicy(value: unknown): ModelAttestationPolicy {
  const policy = requireInputObject(value, 'policy');
  rejectUnknownInputKeys(policy, 'policy', [
    'acceptedTcbStatuses',
    'gpuEvidence',
  ]);

  const acceptedTcbStatuses = parseAcceptedTcbStatuses(
    policy.acceptedTcbStatuses,
  );
  const gpuEvidence = parseGpuEvidenceRequirement(policy.gpuEvidence);

  return {
    ...(acceptedTcbStatuses !== undefined ? { acceptedTcbStatuses } : {}),
    ...(gpuEvidence !== undefined ? { gpuEvidence } : {}),
  };
}

function parseGpuEvidenceRequirement(
  value: unknown,
): ModelAttestationPolicy['gpuEvidence'] {
  if (value === undefined) {
    return undefined;
  }
  if (value === 'if-present' || value === 'required') {
    return value;
  }
  throw inputError('policy.gpuEvidence', 'unsupported_value', {
    expected: "'if-present' or 'required'",
  });
}

function parseModelAttestationVerifiers(
  value: unknown,
): ModelAttestationVerifiers {
  const verifiers = requireInputObject(value, 'verifiers');
  rejectUnknownInputKeys(verifiers, 'verifiers', [
    'quote',
    'deployment',
    'nvidia',
  ]);

  const quote = optionalInputFunction(verifiers.quote, 'verifiers.quote');
  const deployment = optionalInputFunction(
    verifiers.deployment,
    'verifiers.deployment',
  );
  const nvidia = optionalInputFunction(verifiers.nvidia, 'verifiers.nvidia');

  return {
    ...(quote !== undefined
      ? { quote: quote as ModelAttestationVerifiers['quote'] }
      : {}),
    ...(deployment !== undefined
      ? { deployment: deployment as ModelAttestationVerifiers['deployment'] }
      : {}),
    ...(nvidia !== undefined
      ? { nvidia: nvidia as ModelAttestationVerifiers['nvidia'] }
      : {}),
  };
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
  return policy?.gpuEvidence ?? 'if-present';
}
