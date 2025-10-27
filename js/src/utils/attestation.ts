import {
  ModelAttestationVerification,
  GatewayAttestation,
  ModelAttestation,
  GatewayAttestationVerification,
} from '../types/attestation';
import { assertIntelTdxVerified, verifyIntelTdx } from './intel';
import { assertNvidiaGpuVerified, verifyNvidiaGpu } from './nvidia';
import { ETHEREUM_ZERO_ADDRESS } from './consts';

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

export function assertGatewayAttestationVerified(
  verification: GatewayAttestationVerification,
  requestNonce: string,
) {
  assertIntelTdxVerified(
    verification.intel,
    requestNonce,
    ETHEREUM_ZERO_ADDRESS,
  );
}

export async function verifyGatewayAttestation(
  attestation: GatewayAttestation,
): Promise<GatewayAttestationVerification> {
  return {
    intel: await verifyIntelTdx(attestation.intel_quote),
  };
}
