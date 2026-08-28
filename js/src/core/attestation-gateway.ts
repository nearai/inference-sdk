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
 * Verify Gateway evidence and, when available, bind its declared TLS
 * fingerprint to the peer observed by the client.
 */
export async function verifyGatewayAttestation({
  attestation,
  clientBinding,
  policy,
  verifiers,
}: VerifyGatewayAttestationParams): Promise<VerifiedGatewayAttestation> {
  const verifiedQuote = await verifyDstackQuote({
    attestation,
    nonce: clientBinding.nonce,
    policy,
    quoteVerifier: verifiers?.quote,
    advertisedReportData: attestation.reportedQuoteData,
  });
  const tlsBinding = await verifyGatewayReportDataBinding({
    reportData: verifiedQuote.quote.reportData,
    nonce: clientBinding.nonce,
    signingAddress: verifiedQuote.signer.signingAddress,
    reportedSpkiFingerprint: attestation.declaredSpkiFingerprint,
    peerSpkiFingerprint: clientBinding.peerSpkiFingerprint,
  });
  const evidence = await verifyDstackDeployment(
    verifiedQuote,
    verifiers?.deployment,
  );

  return { ...evidence, tlsBinding };
}
