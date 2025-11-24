import { GatewayAttestation } from '../types/attestation-gateway';
import { fetchIntelTdxVerificationData } from '../utils/intel';
import {
  getComposeFromTcbInfo,
  verifyCompose,
  verifyIntelQuoteReportDataForAttestationReport,
} from './attestation-common';
import { IntelTdxVerificationData } from '../types/intel';
import { VerificationError } from '../utils/errors';
import { ETHEREUM_ZERO_ADDRESS } from '../utils/consts';

export async function verifyGatewayAttestation(
  attestation: GatewayAttestation,
) {
  const verificationData = await fetchIntelTdxVerificationData(
    attestation.intel_quote,
  );
  verifyIntelTdxForGateway(
    verificationData,
    attestation.request_nonce,
    attestation.signing_address,
  );

  await verifyCompose(getComposeFromTcbInfo(attestation.info.tcb_info));
}

function verifyIntelTdxForGateway(
  verificationData: IntelTdxVerificationData,
  requestNonce: string,
  signingAddress = ETHEREUM_ZERO_ADDRESS,
) {
  if (!verificationData.quote.verified) {
    throw new VerificationError('Intel quote not verified');
  }

  verifyIntelQuoteReportDataForAttestationReport(
    verificationData.quote.body.reportdata,
    requestNonce,
    signingAddress,
  );
}
