import type {
  VerifiedDirectAttestationReport,
  VerifiedDirectModelAttestation,
  VerifyDirectAttestationReportParams,
  VerifyDirectModelAttestationParams,
} from '../types/direct-verification';
import { VerificationError } from '../utils/errors';
import {
  verifyPeerSpkiFingerprint,
  verifyReportDataBinding,
  verifyReportDataBindingWithTlsFingerprint,
} from './attestation-common';
import { verifyModelDeployment } from './attestation-model';
import { verifyDstackQuote } from './dstack-attestation';

/**
 * Verify one direct model report. Its optional fingerprint is authenticated by
 * the quote, without claiming a connection to that individual instance.
 */
export async function verifyDirectModelAttestation({
  attestation,
  clientBinding,
  policy,
  verifiers,
}: VerifyDirectModelAttestationParams): Promise<VerifiedDirectModelAttestation> {
  const { nonce } = clientBinding;
  const verifiedQuote = await verifyDstackQuote({
    attestation,
    nonce,
    policy,
    quoteVerifier: verifiers?.quote,
    advertisedReportData: attestation.reportedQuoteData,
  });
  let spkiFingerprint: string | undefined;
  if (attestation.spkiFingerprint !== undefined) {
    spkiFingerprint = await verifyReportDataBindingWithTlsFingerprint({
      reportData: verifiedQuote.quote.reportData,
      nonce,
      signingAddress: verifiedQuote.signer.signingAddress,
      reportedSpkiFingerprint: attestation.spkiFingerprint,
    });
  } else {
    verifyReportDataBinding({
      reportData: verifiedQuote.quote.reportData,
      nonce,
      signingAddress: verifiedQuote.signer.signingAddress,
    });
  }
  const verified = await verifyModelDeployment({
    attestation,
    verifiedQuote,
    nonce,
    policy,
    verifiers,
  });
  return {
    ...verified,
    modelName: attestation.modelName,
    ...(attestation.instanceId === undefined
      ? {}
      : { instanceId: attestation.instanceId }),
    ...(spkiFingerprint === undefined ? {} : { spkiFingerprint }),
  };
}

/**
 * Verify every supplied instance report, then bind the top-level report to the
 * TLS peer observed for this request. Shared signing keys do not make reports
 * interchangeable: each instance's measurements and GPU evidence are checked.
 */
export async function verifyDirectAttestationReport({
  report,
  clientBinding,
  policy,
  verifiers,
}: VerifyDirectAttestationReportParams): Promise<VerifiedDirectAttestationReport> {
  if (report.attestations.length === 0) {
    throw new VerificationError({ code: 'policy.model_attestation_required' });
  }
  const attestations: VerifiedDirectModelAttestation[] = [];
  for (const attestation of report.attestations) {
    const verified = await verifyDirectModelAttestation({
      attestation,
      clientBinding,
      policy,
      verifiers,
    });
    attestations.push(verified);
  }

  // The HTTP decoder reuses the array entry when it is identical to the root.
  // Reuse only that object, never another instance with the same signer.
  const rootIndex = report.attestations.indexOf(report.attestation);
  const attestation =
    attestations[rootIndex] ??
    (await verifyDirectModelAttestation({
      attestation: report.attestation,
      clientBinding,
      policy,
      verifiers,
    }));

  let tlsBinding: VerifiedDirectAttestationReport['tlsBinding'];
  if (attestation.spkiFingerprint !== undefined) {
    const peerSpkiFingerprint = clientBinding.spkiFingerprint;
    if (peerSpkiFingerprint === undefined) {
      throw new VerificationError({
        code: 'binding.spki_fingerprint_required',
      });
    }
    verifyPeerSpkiFingerprint(attestation.spkiFingerprint, peerSpkiFingerprint);
    tlsBinding = {
      kind: 'attested',
      spkiFingerprint: attestation.spkiFingerprint,
    };
  } else {
    tlsBinding = { kind: 'none' };
  }
  return { attestation, attestations, tlsBinding };
}
