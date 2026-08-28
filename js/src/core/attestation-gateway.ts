import type {
  VerifiedGatewayAttestation,
  VerifyGatewayAttestationParams,
} from '../types/verification';
import { verifyGatewayReportDataBinding } from './attestation-common';
import {
  verifyDstackDeployment,
  verifyDstackQuote,
} from './dstack-attestation';

/**
 * Verify gateway evidence and bind it to a TLS peer fingerprint independently
 * observed by the client.
 */
export async function verifyGatewayAttestation({
  attestation,
  nonce,
  peerSpkiFingerprint,
  policy,
  verifiers,
}: VerifyGatewayAttestationParams): Promise<VerifiedGatewayAttestation> {
  const verifiedQuote = await verifyDstackQuote({
    attestation,
    nonce,
    policy,
    quoteVerifier: verifiers?.quote,
    advertisedReportData: attestation.reportedQuoteData,
  });
  const tlsBinding = await verifyGatewayReportDataBinding({
    reportData: verifiedQuote.quote.reportData,
    nonce,
    signingAddress: verifiedQuote.signer.signingAddress,
    reportedSpkiFingerprint: verifiedQuote.attestation.declaredSpkiFingerprint,
    peerSpkiFingerprint,
  });
  const evidence = await verifyDstackDeployment(
    verifiedQuote,
    verifiers?.deployment,
  );

  return { ...evidence, tlsBinding };
}
