import {
  ModelAttestationVerification,
  GatewayAttestation,
  ModelAttestation,
  GatewayAttestationVerification,
} from '../types/attestation';
import { isIntelTdxVerified, verifyIntelTdx } from './intel';
import { isNvidiaGpuVerified, verifyNvidiaGpu } from './nvidia';
import { ETHEREUM_ZERO_ADDRESS } from './consts';

export function isModelAttestationReportVerified(
  verification: ModelAttestationVerification,
  requestNonce: string,
  signingAddress: string,
): boolean {
  return (
    isIntelTdxVerified(verification.intel, requestNonce, signingAddress) &&
    isNvidiaGpuVerified(verification.nvidia)
  );
}

export async function verifyModelAttestation(
  attestation: ModelAttestation,
): Promise<ModelAttestationVerification> {
  return {
    intel: await verifyIntelTdx(attestation.intel_quote),
    nvidia: await verifyNvidiaGpu(attestation.nvidia_payload),
  };
}

export function isGatewayAttestationReportVerified(
  verification: GatewayAttestationVerification,
  requestNonce: string,
): boolean {
  return isIntelTdxVerified(
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
