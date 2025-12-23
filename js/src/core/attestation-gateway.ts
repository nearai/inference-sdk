import {
  GatewayAttestation,
  VerifyGatewayAttestationConfig,
} from '../types/attestation-gateway';
import { fetchIntelTdxVerificationData } from '../utils/intel';
import {
  getComposeFromTcbInfo,
  verifyCompose,
  verifyIntelQuoteReportDataForAttestationReport,
} from './attestation-common';
import { IntelTdxVerificationData } from '../types/intel';
import { VerificationError } from '../utils/errors';
import { ETHEREUM_ZERO_ADDRESS, TIMEOUT } from '../utils/consts';
import { fetchTimeout } from '../utils/fetch';

export async function verifyGatewayAttestation(
  attestation: GatewayAttestation,
  config: VerifyGatewayAttestationConfig,
) {
  const verificationData = await fetchIntelTdxVerificationData(
    attestation.intel_quote,
  );
  verifyIntelTdxForGateway(
    verificationData,
    attestation.request_nonce,
    attestation.signing_address,
  );

  await verifyVpcForGateway(
    config.domain,
    attestation.vpc.vpc_server_app_id,
    attestation.vpc.vpc_hostname,
  );

  if (config.imageNamesOfSigstoreHash.length > 0) {
    await verifyCompose(
      getComposeFromTcbInfo(attestation.info.tcb_info),
      config.imageNamesOfSigstoreHash,
    );
  }
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

async function verifyVpcForGateway(
  domain: string,
  vpcServerAppId: string,
  vpcHostname: string,
) {
  const url = `https://${domain}/evidences/vpc.json`;

  const response = await fetchTimeout(url, TIMEOUT);

  if (!response.ok) {
    throw new VerificationError(
      `Failed to fetch VPC info with status code ${response.status}`,
    );
  }

  const vpcInfo = await response.json();

  if (vpcInfo.vpc_server_app_id !== vpcServerAppId) {
    throw new VerificationError('vpc_server_app_id mismatching');
  }

  if (!vpcInfo.nodes.includes(vpcHostname)) {
    throw new VerificationError('vpc_hostname mismatching');
  }
}
