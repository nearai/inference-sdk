import {
  AttestationReport,
  AttestationReportVerification,
} from '../types/attestation';
import { isIntelTdxVerified, verifyIntelTdx } from './intel';
import { isNvidiaGpuVerified, verifyNvidiaGpu } from './nvidia';
import { ETHEREUM_ZERO_ADDRESS } from './consts';

export function isModelAttestationReportVerified(
  verification: AttestationReportVerification,
  requestNonce: string,
  signingAddress: string,
): boolean {
  return (
    isIntelTdxVerified(verification.intel, requestNonce, signingAddress) &&
    isNvidiaGpuVerified(verification.nvidia)
  );
}

export function isGatewayAttestationReportVerified(
  verification: AttestationReportVerification,
  requestNonce: string,
): boolean {
  return isIntelTdxVerified(
    verification.intel,
    requestNonce,
    ETHEREUM_ZERO_ADDRESS,
  );
}

export async function verifyAttestationReport(
  report: AttestationReport,
): Promise<AttestationReportVerification> {
  return {
    intel: await verifyIntelTdx(report.intel_quote),
    nvidia: await verifyNvidiaGpu(report.nvidia_payload),
  };
}
