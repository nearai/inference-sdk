import type {
  GatewayAttestationPolicy,
  VerifiedGatewayAttestation,
  VerifyGatewayAttestationParams,
} from '../types/verification';
import { VerificationError } from '../utils/errors';
import {
  verifyReportDataBinding,
  verifyReportDataBindingWithTlsFingerprint,
} from './attestation-common';
import {
  verifyDstackDeployment,
  verifyDstackQuote,
} from './dstack-attestation';

/**
 * Verify Gateway evidence. TLS binding is required by default. When disabled,
 * verification uses the signer-and-nonce report-data layout instead.
 */
export async function verifyGatewayAttestation({
  attestation,
  clientBinding,
  policy,
  verifiers,
}: VerifyGatewayAttestationParams): Promise<VerifiedGatewayAttestation> {
  const verifyTlsBinding = shouldVerifyTlsBinding(policy);
  const verifiedQuote = await verifyDstackQuote({
    attestation,
    nonce: clientBinding.nonce,
    policy,
    quoteVerifier: verifiers?.quote,
    advertisedReportData: attestation.reportedQuoteData,
  });
  let tlsBinding: VerifiedGatewayAttestation['tlsBinding'];
  if (verifyTlsBinding) {
    const peerTlsSpkiFingerprint = clientBinding.peerSpkiFingerprint;
    if (peerTlsSpkiFingerprint === undefined) {
      throw new VerificationError({
        code: 'policy.tls_binding_required',
      });
    }
    const spkiFingerprint = await verifyReportDataBindingWithTlsFingerprint({
      reportData: verifiedQuote.quote.reportData,
      nonce: clientBinding.nonce,
      signingAddress: verifiedQuote.signer.signingAddress,
      reportedTlsSpkiFingerprint: attestation.tlsSpkiFingerprint,
      peerTlsSpkiFingerprint,
    });
    tlsBinding = { kind: 'attested', spkiFingerprint };
  } else {
    verifyReportDataBinding({
      reportData: verifiedQuote.quote.reportData,
      nonce: clientBinding.nonce,
      signingAddress: verifiedQuote.signer.signingAddress,
    });
    tlsBinding = { kind: 'none' };
  }
  const evidence = await verifyDstackDeployment(
    verifiedQuote,
    verifiers?.deployment,
  );

  return { ...evidence, tlsBinding };
}

function shouldVerifyTlsBinding(
  policy: GatewayAttestationPolicy | undefined,
): boolean {
  return policy?.verifyTlsBinding ?? true;
}
