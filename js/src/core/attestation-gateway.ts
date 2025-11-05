import {
  GatewayAttestation,
  GatewayAttestationVerification,
} from '../types/attestation-gateway';
import { assertIntelTdxVerified, verifyIntelTdx } from '../utils/intel';
import { ETHEREUM_ZERO_ADDRESS } from '../utils/consts';

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
