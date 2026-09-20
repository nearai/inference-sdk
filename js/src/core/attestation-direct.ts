import type {
  VerifiedDirectModelAttestations,
  VerifiedDirectModelAttestation,
  VerifyDirectModelAttestationsParams,
  VerifyDirectModelAttestationParams,
} from '../types/direct-verification';
import { VerificationError } from '../utils/errors';
import {
  verifyPeerSpkiFingerprint,
  verifyReportDataBinding,
  verifyReportDataBindingWithTlsFingerprint,
} from './attestation-common';
import {
  verifyModelDeployment,
  verifyModelGpuEvidence,
} from './attestation-model';
import { verifyDstackQuote } from './dstack-attestation';

/**
 * Verify one direct model attestation. Its optional fingerprint is authenticated by
 * the quote, without claiming a connection to that individual instance.
 */
export async function verifyDirectModelAttestation(
  params: VerifyDirectModelAttestationParams,
): Promise<VerifiedDirectModelAttestation> {
  const [deployment, gpuEvidence] = await Promise.all([
    verifyDirectModelCpuAttestation(params),
    verifyModelGpuEvidence(params),
  ]);
  return { ...deployment, gpuEvidence };
}

type VerifiedDirectModelDeployment = Omit<
  VerifiedDirectModelAttestation,
  'gpuEvidence'
>;

async function verifyDirectModelCpuAttestation({
  attestation,
  clientBinding,
  policy,
  verifiers,
}: VerifyDirectModelAttestationParams): Promise<VerifiedDirectModelDeployment> {
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
    deploymentVerifier: verifiers?.deployment,
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
 * Verify every supplied model attestation, then bind the serving attestation
 * to the TLS peer observed for this request. Shared signing keys do not make
 * instances interchangeable: each instance's measurements and GPU evidence
 * are checked.
 */
export async function verifyDirectModelAttestations({
  servingAttestation,
  attestations: suppliedAttestations,
  clientBinding,
  policy,
  verifiers,
}: VerifyDirectModelAttestationsParams): Promise<VerifiedDirectModelAttestations> {
  if (suppliedAttestations.length === 0) {
    throw new VerificationError({ code: 'policy.model_attestation_required' });
  }
  const attestations = await Promise.all(
    suppliedAttestations.map((attestation) =>
      verifyDirectModelAttestation({
        attestation,
        clientBinding,
        policy,
        verifiers,
      }),
    ),
  );
  const verifiedServingAttestation =
    attestations[suppliedAttestations.indexOf(servingAttestation)];

  if (verifiedServingAttestation === undefined) {
    throw new VerificationError({
      code: 'input.invalid',
      details: {
        field: 'servingAttestation',
        reason: 'not_in_attestation_set',
      },
    });
  }

  let tlsBinding: VerifiedDirectModelAttestations['tlsBinding'];
  if (verifiedServingAttestation.spkiFingerprint !== undefined) {
    const peerSpkiFingerprint = clientBinding.spkiFingerprint;
    if (peerSpkiFingerprint === undefined) {
      throw new VerificationError({
        code: 'binding.spki_fingerprint_required',
      });
    }
    verifyPeerSpkiFingerprint(
      verifiedServingAttestation.spkiFingerprint,
      peerSpkiFingerprint,
    );
    tlsBinding = {
      kind: 'attested',
      spkiFingerprint: verifiedServingAttestation.spkiFingerprint,
    };
  } else {
    tlsBinding = { kind: 'none' };
  }
  return {
    servingAttestation: verifiedServingAttestation,
    attestations,
    tlsBinding,
    spkiFingerprints: getDirectSpkiFingerprints(attestations),
  };
}

/** Return distinct quote-authenticated SPKI fingerprints in response order. */
export function getDirectSpkiFingerprints(
  attestations: readonly VerifiedDirectModelAttestation[],
): readonly string[] {
  const fingerprints = new Set<string>();
  for (const attestation of attestations) {
    if (attestation.spkiFingerprint !== undefined) {
      fingerprints.add(attestation.spkiFingerprint);
    }
  }
  return [...fingerprints];
}
