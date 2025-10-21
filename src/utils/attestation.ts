import {
  AttestationReport,
  AttestationReportVerification,
} from '../types/attestation';
import { isIntelTdxVerified, verifyIntelTdx } from './intel';
import { isNvidiaGpuVerified, verifyNvidiaGpu } from './nvidia';

export function isAttestationReportVerified(
  verification: AttestationReportVerification,
  report: AttestationReport,
  requestNonce: string,
): boolean {
  return (
    isIntelTdxVerified(
      verification.intel,
      report.signing_address,
      requestNonce,
    ) && isNvidiaGpuVerified(verification.nvidia)
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
