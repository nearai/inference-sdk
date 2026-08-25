import {
  VerifiedGatewayAttestation,
  VerifyGatewayAttestationInput,
} from '../types/verification';
import { verifyStrictReportDataBinding } from './attestation-common';
import { verifyDstackAttestation } from './dstack-attestation';

/**
 * Verify gateway evidence and bind it to the client's live gateway TLS
 * connection. The caller must obtain the peer SPKI on that same connection.
 */
export async function verifyGatewayAttestation(
  input: VerifyGatewayAttestationInput,
): Promise<VerifiedGatewayAttestation> {
  const { attestation } = input;
  const evidence = await verifyDstackAttestation({
    attestation,
    expectedNonce: input.expectedNonce,
    quoteVerifier: input.quoteVerifier,
    provenanceVerifier: input.provenanceVerifier,
    policy: input.policy,
    verifyGpu: false,
    advertisedReportData: attestation.report_data,
    verifyReportDataBinding: (reportData) =>
      verifyStrictReportDataBinding({
        reportData,
        expectedNonce: input.expectedNonce,
        signingAddress: attestation.signing_address,
        reportedTlsCertFingerprint: attestation.tls_cert_fingerprint,
        peerTlsCertFingerprint: input.peerTlsCertFingerprint,
      }),
  });

  return {
    ...evidence,
    kind: 'gateway',
  };
}
