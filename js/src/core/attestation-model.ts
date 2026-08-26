import type {
  VerifiedNearModelAttestation,
  VerifyNearModelAttestationInput,
} from '../types/verification';
import { verifyCloudModelReportDataBinding } from './attestation-common';
import { verifyDstackAttestation } from './dstack-attestation';

/**
 * Verify model evidence returned through NEAR AI Cloud. This verifies freshness
 * and the model signing identity but does not claim a client-to-model TLS
 * binding; the client's TLS connection terminates at the gateway.
 */
export async function verifyNearModelAttestation(
  input: VerifyNearModelAttestationInput,
): Promise<VerifiedNearModelAttestation> {
  const { attestation } = input;
  const evidence = await verifyDstackAttestation({
    target: 'near_model',
    attestation,
    expectedNonce: input.expectedNonce,
    quoteVerifier: input.quoteVerifier,
    gpuVerifier: input.gpuVerifier,
    provenanceVerifier: input.provenanceVerifier,
    policy: input.policy,
    nvidiaPayload: attestation.nvidia_payload,
    verifyGpu: true,
    advertisedReportData: attestation.report_data,
    verifyReportDataBinding: (reportData) =>
      verifyCloudModelReportDataBinding({
        reportData,
        expectedNonce: input.expectedNonce,
        signingAddress: attestation.signing_address,
        reportedTlsCertFingerprint: attestation.tls_cert_fingerprint,
      }),
  });

  return { ...evidence, kind: 'near_model' };
}
