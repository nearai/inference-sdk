import { GatewayAttestation } from '../types/attestation-gateway';
import { fetchIntelTdxVerificationData } from '../utils/intel';
import { verifyIntelQuoteReportDataForAttestationReport } from './common';
import { IntelTdxVerificationData } from '../types/intel';
import { VerificationError } from '../utils/errors';
import { ETHEREUM_ZERO_ADDRESS } from '../utils/consts';

export async function verifyGatewayAttestation(
  attestation: GatewayAttestation,
  requestNonce: string,
) {
  const verificationData = await fetchIntelTdxVerificationData(
    attestation.intel_quote,
  );
  verifyIntelTdxForGateway(verificationData, requestNonce);
}

function verifyIntelTdxForGateway(
  verificationData: IntelTdxVerificationData,
  requestNonce: string,
) {
  if (!verificationData.quote.verified) {
    throw new VerificationError('Intel quote not verified');
  }

  verifyIntelQuoteReportDataForAttestationReport(
    verificationData.quote.body.reportdata,
    requestNonce,
    ETHEREUM_ZERO_ADDRESS,
  );
}
