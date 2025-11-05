import { GatewayAttestation } from '../types/attestation-gateway';
import { checkIntelTdxVerification, verifyIntelTdx } from '../utils/intel';
import { ETHEREUM_ZERO_ADDRESS } from '../utils/consts';

export async function verifyGatewayAttestation(
  attestation: GatewayAttestation,
  requestNonce: string,
) {
  const intelTdxVerification = await verifyIntelTdx(attestation.intel_quote);
  checkIntelTdxVerification(
    intelTdxVerification,
    requestNonce,
    ETHEREUM_ZERO_ADDRESS,
  );
}
