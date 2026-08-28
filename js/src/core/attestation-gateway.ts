import type {
  GatewayAttestationPolicy,
  VerifiedGatewayAttestation,
  VerifyGatewayAttestationParams,
} from '../types/verification';
import { VerificationError } from '../utils/errors';
import { verifyGatewayReportDataBinding } from './attestation-common';
import {
  verifyDstackDeployment,
  verifyDstackQuote,
} from './dstack-attestation';

/**
 * Verify Gateway evidence. Peer TLS binding is required by default and can be
 * disabled explicitly for runtimes that cannot observe the peer certificate.
 */
export async function verifyGatewayAttestation({
  attestation,
  clientBinding,
  policy,
  verifiers,
}: VerifyGatewayAttestationParams): Promise<VerifiedGatewayAttestation> {
  const verifyPeerTlsBinding = shouldVerifyPeerTlsBinding(policy);
  if (verifyPeerTlsBinding && clientBinding.peerSpkiFingerprint === undefined) {
    throw new VerificationError({
      code: 'policy.peer_tls_binding_required',
    });
  }
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
    peerSpkiFingerprint: verifyPeerTlsBinding
      ? clientBinding.peerSpkiFingerprint
      : undefined,
  });
  const evidence = await verifyDstackDeployment(
    verifiedQuote,
    verifiers?.deployment,
  );

  return { ...evidence, tlsBinding };
}

function shouldVerifyPeerTlsBinding(
  policy: GatewayAttestationPolicy | undefined,
): boolean {
  return policy?.verifyPeerTlsBinding ?? true;
}
