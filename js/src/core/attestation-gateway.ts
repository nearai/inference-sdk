import type {
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

/** Verify Gateway evidence using the report-data layout returned by Cloud API. */
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
  let tlsBinding: VerifiedGatewayAttestation['tlsBinding'];
  if (attestation.spkiFingerprint !== undefined) {
    const peerSpkiFingerprint = clientBinding.spkiFingerprint;
    if (peerSpkiFingerprint === undefined) {
      throw new VerificationError({
        code: 'binding.spki_fingerprint_required',
      });
    }
    const spkiFingerprint = await verifyReportDataBindingWithTlsFingerprint({
      reportData: verifiedQuote.quote.reportData,
      nonce: clientBinding.nonce,
      signingAddress: verifiedQuote.signer.signingAddress,
      reportedSpkiFingerprint: attestation.spkiFingerprint,
      peerSpkiFingerprint,
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
