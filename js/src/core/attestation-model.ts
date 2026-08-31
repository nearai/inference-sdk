import type {
  GpuEvidenceStatus,
  ModelAttestationPolicy,
  NvidiaEvidenceVerifier,
  VerifiedModelAttestation,
  VerifyModelAttestationParams,
} from '../types/verification';
import * as v from 'valibot';
import { NvidiaPayloadNonceSchema } from '../schemas';
import { VerificationError, wrapVerificationError } from '../utils/errors';
import { nvidiaNrasVerifier } from '../utils/nvidia';
import {
  verifyReportDataBinding,
  verifyReportedNonce,
} from './attestation-common';
import {
  verifyDstackDeployment,
  verifyDstackQuote,
} from './dstack-attestation';

/**
 * Verify model evidence returned through NEAR AI Cloud. This verifies freshness
 * and the model signing identity but does not claim a client-to-model TLS
 * binding; the client's TLS connection terminates at the gateway.
 */
export async function verifyModelAttestation({
  attestation,
  clientBinding,
  policy,
  verifiers,
}: VerifyModelAttestationParams): Promise<VerifiedModelAttestation> {
  const { nonce } = clientBinding;
  const verifiedQuote = await verifyDstackQuote({
    attestation,
    nonce,
    policy,
    quoteVerifier: verifiers?.quote,
    advertisedReportData: attestation.reportedQuoteData,
  });
  verifyReportDataBinding({
    reportData: verifiedQuote.quote.reportData,
    nonce,
    signingAddress: verifiedQuote.signer.signingAddress,
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

  return { ...evidence, gpuEvidence };
}

type VerifyNvidiaEvidenceParams = {
  payload?: string;
  nonce: string;
  requirement: 'if-present' | 'required';
  verifier: NvidiaEvidenceVerifier;
};

async function verifyNvidiaEvidence(
  input: VerifyNvidiaEvidenceParams,
): Promise<GpuEvidenceStatus> {
  if (input.payload === undefined) {
    if (input.requirement === 'required') {
      throw new VerificationError({
        code: 'policy.gpu_evidence_required',
      });
    }
    return 'not_provided';
  }

  // Bind the provider payload to the same nonce before handing it to either
  // the default NRAS verifier or a caller-supplied NVIDIA verifier.
  let payload: unknown;
  try {
    payload = JSON.parse(input.payload);
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'gpu.payload_invalid',
        details: { reason: 'invalid_json' },
      },
      { cause },
    );
  }
  const parsed = v.safeParse(NvidiaPayloadNonceSchema, payload);
  if (!parsed.success) {
    throw new VerificationError({
      code: 'gpu.payload_invalid',
      details: { reason: 'nonce_missing' },
    });
  }
  verifyReportedNonce({
    reportedNonce: parsed.output.nonce,
    nonce: input.nonce,
    source: 'nvidiaPayload',
  });

  try {
    await input.verifier(input.payload);
  } catch (cause) {
    throw wrapVerificationError(
      {
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
