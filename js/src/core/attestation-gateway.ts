import { GatewayAttestation } from '../types/attestation-gateway';
import { verifyIntelTdx, fetchIntelTdxVerificationData } from '../utils/intel';
import { ETHEREUM_ZERO_ADDRESS } from '../utils/consts';

export async function verifyGatewayAttestation(
  attestation: GatewayAttestation,
  requestNonce: string,
) {
  const intelTdxVerificationData = await fetchIntelTdxVerificationData(
    attestation.intel_quote,
  );
  verifyIntelTdx(intelTdxVerificationData, requestNonce, ETHEREUM_ZERO_ADDRESS);
}
