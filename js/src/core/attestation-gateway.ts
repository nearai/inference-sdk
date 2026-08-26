import type {
  VerifiedGatewayAttestation,
  VerifyGatewayAttestationInput,
} from '../types/verification';
import { VerifyGatewayAttestationInputSchema } from '../schemas';
import { parsePublicInput } from '../utils/schema';
import { verifyGatewayReportDataBinding } from './attestation-common';
import {
  requireAttestationEvidence,
  verifyDstackDeployment,
  verifyDstackQuote,
} from './dstack-attestation';
import { markVerifiedGatewayAttestation } from './verified-attestation';

/**
 * Verify gateway evidence and bind it to the client's live gateway TLS
 * connection. The caller must obtain the peer SPKI on that same connection.
 */
export async function verifyGatewayAttestation(
  input: VerifyGatewayAttestationInput,
): Promise<VerifiedGatewayAttestation> {
  const parsed = parseGatewayAttestationInput(input);
  const { attestation, nonce, peerSpkiFingerprint, policy, verifiers } = parsed;
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
    signingAddress: verifiedQuote.signer.address,
    reportedSpkiFingerprint: verifiedQuote.attestation.declaredSpkiFingerprint,
    peerSpkiFingerprint,
  });
  const evidence = await verifyDstackDeployment(
    verifiedQuote,
    verifiers?.deployment,
  );

  return markVerifiedGatewayAttestation({ ...evidence, tlsBinding });
}

type ParsedGatewayAttestationInput = VerifyGatewayAttestationInput;

function parseGatewayAttestationInput(
  input: unknown,
): ParsedGatewayAttestationInput {
  const parsed = parsePublicInput(
    VerifyGatewayAttestationInputSchema,
    input,
    'input',
  );
  const baseAttestation = requireAttestationEvidence(parsed.attestation);

  return {
    ...parsed,
    attestation: Object.freeze({
      ...baseAttestation,
      reportedQuoteData: parsed.attestation.reportedQuoteData,
    }),
  };
}
