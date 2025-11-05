import {
  ModelAttestationVerification,
  ModelAttestation,
} from '../types/attestation-model';
import { assertIntelTdxVerified, verifyIntelTdx } from './intel';
import { assertNvidiaGpuVerified, verifyNvidiaGpu } from './nvidia';

export function assertModelAttestationVerified(
  verification: ModelAttestationVerification,
  requestNonce: string,
  signingAddress: string,
) {
  assertIntelTdxVerified(verification.intel, requestNonce, signingAddress);
  assertNvidiaGpuVerified(verification.nvidia);
}

export async function verifyModelAttestation(
  attestation: ModelAttestation,
): Promise<ModelAttestationVerification> {
  return {
    intel: await verifyIntelTdx(attestation.intel_quote),
    nvidia: await verifyNvidiaGpu(attestation.nvidia_payload),
  };
}
