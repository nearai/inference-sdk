import type {
  VerifiedGatewayAttestation,
  VerifyGatewayAttestationParams,
} from '../types/verification';
import { VerificationError } from '../utils/errors';
import {
  verifyPeerSpkiFingerprint,
  verifyReportDataBinding,
  verifyReportDataBindingWithTlsFingerprint,
} from './attestation-common';
import {
  verifyDstackDeployment,
  verifyDstackQuote,
} from './dstack-attestation';
import { runDeploymentVerifier } from './deployment-verifier';
import { createVerificationContext } from './verification-context';

/** Verify Gateway evidence using the report-data layout returned by Cloud API. */
export async function verifyGatewayAttestation({
  attestation,
  clientBinding,
  policy,
  verifiers,
  context = createVerificationContext(),
  signal,
}: VerifyGatewayAttestationParams): Promise<VerifiedGatewayAttestation> {
  const verifiedQuote = await verifyDstackQuote({
    attestation,
    nonce: clientBinding.nonce,
    policy,
    tdxQuoteVerifier: verifiers?.tdxQuote,
    advertisedReportData: attestation.reportedQuoteData,
    context,
    signal,
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
    });
    verifyPeerSpkiFingerprint(spkiFingerprint, peerSpkiFingerprint);
    tlsBinding = { kind: 'attested', spkiFingerprint };
  } else {
    verifyReportDataBinding({
      reportData: verifiedQuote.quote.reportData,
      nonce: clientBinding.nonce,
      signingAddress: verifiedQuote.signer.signingAddress,
    });
    tlsBinding = { kind: 'none' };
  }
  const deployment = await verifyDstackDeployment(verifiedQuote);
  const deploymentProvenance = await runDeploymentVerifier(
    deployment,
    verifiers?.deployment,
  );

  return {
    signer: verifiedQuote.signer,
    tcbStatus: verifiedQuote.quote.tcbStatus,
    advisoryIds: verifiedQuote.quote.advisoryIds,
    deployment,
    deploymentProvenance,
    tlsBinding,
    report: attestation,
  };
}
