import type {
  GpuEvidenceStatus,
  ModelAttestationPolicy,
  NvidiaEvidenceVerifier,
  VerifiedModelAttestation,
  VerifyModelAttestationInput,
} from '../types/verification';
import { VerifyModelAttestationInputSchema } from '../schemas';
import { VerificationError, wrapVerificationError } from '../utils/errors';
import { nvidiaNrasVerifier } from '../utils/nvidia';
import { parsePublicInput } from '../utils/schema';
import {
  verifyCloudModelReportDataBinding,
  verifyReportedNonce,
} from './attestation-common';
import {
  verifyDstackDeployment,
  verifyDstackQuote,
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
    signingAddress: verifiedQuote.signer.address,
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

  return markVerifiedModelAttestation({ ...evidence, tlsBinding, gpuEvidence });
}

type ParsedModelAttestationInput = VerifyModelAttestationInput;

function parseModelAttestationInput(
  input: unknown,
): ParsedModelAttestationInput {
  const parsed = parsePublicInput(
    VerifyModelAttestationInputSchema,
    input,
    'input',
  );
  const baseAttestation = requireAttestationEvidence(parsed.attestation);

  return {
    ...parsed,
    attestation: Object.freeze({
      ...baseAttestation,
      ...(parsed.attestation.nvidiaPayload !== undefined
        ? { nvidiaPayload: parsed.attestation.nvidiaPayload }
        : {}),
    }),
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
