import type {
  GpuEvidenceStatus,
  DeploymentVerifier,
  GpuEvidenceVerifier,
  VerifiedModelAttestation,
  VerifyModelAttestationParams,
} from '../types/verification';
import { Buffer } from 'buffer';
import { computeAddress } from 'ethers';
import { decodeNvidiaPayloadNonce } from '../boundaries/nvidia';
import type { SigningAlgo } from '../types/attestation-common';
import type { ModelAttestation } from '../types/attestation-model';
import { hexToBuffer } from '../utils/common';
import { VerificationError, wrapVerificationError } from '../utils/errors';
import { createGpuEvidenceVerifier } from '../utils/nvidia';
import {
  verifyReportDataBinding,
  verifyReportedNonce,
} from './attestation-common';
import {
  verifyDstackDeployment,
  verifyDstackQuote,
} from './dstack-attestation';
import type { VerifiedDstackQuote } from './dstack-attestation';

/**
 * Verify model evidence returned through NEAR AI Cloud. This verifies freshness
 * and the model signing identity but does not claim a client-to-model TLS
 * binding; the client's TLS connection terminates at the gateway.
 */
export async function verifyModelAttestation(
  params: VerifyModelAttestationParams,
): Promise<VerifiedModelAttestation> {
  // CPU and GPU evidence bind independently to the same client nonce.
  const [deployment, gpuEvidence] = await Promise.all([
    verifyModelCpuAttestation(params),
    verifyModelGpuEvidence(params),
  ]);
  return { ...deployment, gpuEvidence };
}

type VerifiedModelDeployment = Omit<VerifiedModelAttestation, 'gpuEvidence'>;

async function verifyModelCpuAttestation({
  attestation,
  clientBinding,
  policy,
  verifiers,
}: VerifyModelAttestationParams): Promise<VerifiedModelDeployment> {
  const { nonce } = clientBinding;
  const verifiedQuote = await verifyDstackQuote({
    attestation,
    nonce,
    policy,
    tdxQuoteVerifier: verifiers?.tdxQuote,
    advertisedReportData: attestation.reportedQuoteData,
  });
  verifyReportDataBinding({
    reportData: verifiedQuote.quote.reportData,
    nonce,
    signingAddress: verifiedQuote.signer.signingAddress,
  });
  return verifyModelDeployment({
    attestation,
    verifiedQuote,
    deploymentVerifier: verifiers?.deployment,
  });
}

type VerifyModelDeploymentParams = {
  attestation: ModelAttestation;
  verifiedQuote: VerifiedDstackQuote;
  deploymentVerifier?: DeploymentVerifier;
};

/** Shared model checks after the endpoint-specific report-data binding passes. */
export async function verifyModelDeployment({
  attestation,
  verifiedQuote,
  deploymentVerifier,
}: VerifyModelDeploymentParams): Promise<VerifiedModelDeployment> {
  const evidence = await verifyDstackDeployment(
    verifiedQuote,
    deploymentVerifier,
  );

  const signingPublicKey = verifySigningPublicKey({
    attestation,
    signingAlgo: evidence.signer.signingAlgo,
    signingAddress: evidence.signer.signingAddress,
  });

  return {
    ...evidence,
    ...(signingPublicKey === undefined ? {} : { signingPublicKey }),
  };
}

/** GPU verification is independent of the model's CPU quote and deployment. */
export function verifyModelGpuEvidence({
  attestation,
  clientBinding: { nonce },
  policy,
  verifiers,
}: VerifyModelAttestationParams): Promise<GpuEvidenceStatus> {
  return verifyGpuEvidence({
    payload: attestation.nvidiaPayload,
    nonce,
    requirement: policy?.gpuEvidence ?? 'if-present',
    verifier: verifiers?.gpuEvidence ?? createGpuEvidenceVerifier(),
  });
}

type VerifySigningPublicKeyParams = {
  readonly attestation: VerifyModelAttestationParams['attestation'];
  readonly signingAlgo: SigningAlgo;
  readonly signingAddress: string;
};

/**
 * When Cloud API supplies a model E2EE public key, bind it to the signer
 * already authenticated by quote report data. Ed25519 signer addresses are
 * the public key itself. ECDSA signer addresses are derived from the raw
 * secp256k1 `X || Y` public key.
 */
function verifySigningPublicKey({
  attestation,
  signingAlgo,
  signingAddress,
}: VerifySigningPublicKeyParams): string | undefined {
  if (attestation.signingPublicKey === undefined) {
    return undefined;
  }
  const signingPublicKey = hexToBuffer(
    attestation.signingPublicKey,
    'attestation.signingPublicKey',
  );
  const verifiedSigningAddress = hexToBuffer(
    signingAddress,
    'signer.signingAddress',
  );
  const publicKeyMatchesSigner =
    signingAlgo === 'ed25519'
      ? signingPublicKey.length === 32 &&
        signingPublicKey.equals(verifiedSigningAddress)
      : ecdsaPublicKeyMatchesSigner(signingPublicKey, verifiedSigningAddress);
  if (!publicKeyMatchesSigner) {
    throw new VerificationError({
      code: 'binding.model_public_key_mismatch',
    });
  }
  return signingAlgo === 'ecdsa' && signingPublicKey.length === 65
    ? signingPublicKey.subarray(1).toString('hex')
    : signingPublicKey.toString('hex');
}

function ecdsaPublicKeyMatchesSigner(
  signingPublicKey: Buffer,
  signingAddress: Buffer,
): boolean {
  const rawPublicKey =
    signingPublicKey.length === 65 && signingPublicKey[0] === 0x04
      ? signingPublicKey.subarray(1)
      : signingPublicKey;
  if (rawPublicKey.length !== 64) {
    return false;
  }

  try {
    const derivedSigningAddress = Buffer.from(
      computeAddress(`0x04${rawPublicKey.toString('hex')}`).slice(2),
      'hex',
    );
    return derivedSigningAddress.equals(signingAddress);
  } catch {
    return false;
  }
}

type VerifyGpuEvidenceParams = {
  payload?: string;
  nonce: string;
  requirement: 'if-present' | 'required';
  verifier: GpuEvidenceVerifier;
};

async function verifyGpuEvidence(
  input: VerifyGpuEvidenceParams,
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
  // the default NRAS verifier or a caller-supplied GPU verifier.
  verifyReportedNonce({
    reportedNonce: decodeNvidiaPayloadNonce(input.payload),
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
