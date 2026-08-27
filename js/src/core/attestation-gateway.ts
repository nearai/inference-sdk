import type {
  AttestationPolicy,
  AttestationVerifiers,
  VerifiedGatewayAttestation,
  VerifyGatewayAttestationInput,
} from '../types/verification';
import {
  optionalInputFunction,
  rejectUnknownInputKeys,
  requireInputObject,
  requireInputString,
} from '../utils/input';
import { verifyGatewayReportDataBinding } from './attestation-common';
import {
  requireAttestationEvidence,
  parseAcceptedTcbStatuses,
  verifyDstackDeployment,
  verifyDstackQuote,
} from './dstack-attestation';
import { markVerifiedGatewayAttestation } from './verified-attestation';

/**
 * Verify gateway evidence and bind it to a TLS peer fingerprint independently
 * observed by the client.
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
  const value = requireInputObject(input, 'input');
  rejectUnknownInputKeys(value, 'input', [
    'attestation',
    'nonce',
    'peerSpkiFingerprint',
    'policy',
    'verifiers',
  ]);

  const attestationInput = requireInputObject(value.attestation, 'attestation');
  rejectUnknownInputKeys(attestationInput, 'attestation', [
    'nonce',
    'signer',
    'intelQuote',
    'eventLog',
    'appCompose',
    'declaredSpkiFingerprint',
    'reportedQuoteData',
  ]);
  const signerInput = requireInputObject(
    attestationInput.signer,
    'attestation.signer',
  );
  rejectUnknownInputKeys(signerInput, 'attestation.signer', [
    'algorithm',
    'address',
  ]);
  const baseAttestation = requireAttestationEvidence(attestationInput);
  const reportedQuoteData = requireInputString(
    attestationInput.reportedQuoteData,
    'attestation.reportedQuoteData',
  );

  return Object.freeze({
    attestation: Object.freeze({
      ...baseAttestation,
      reportedQuoteData,
    }),
    nonce: requireInputString(value.nonce, 'nonce'),
    peerSpkiFingerprint: requireInputString(
      value.peerSpkiFingerprint,
      'peerSpkiFingerprint',
    ),
    ...(value.policy !== undefined
      ? { policy: parseGatewayAttestationPolicy(value.policy) }
      : {}),
    ...(value.verifiers !== undefined
      ? { verifiers: parseGatewayAttestationVerifiers(value.verifiers) }
      : {}),
  });
}

function parseGatewayAttestationPolicy(value: unknown): AttestationPolicy {
  const policy = requireInputObject(value, 'policy');
  rejectUnknownInputKeys(policy, 'policy', ['acceptedTcbStatuses']);

  const acceptedTcbStatuses = parseAcceptedTcbStatuses(
    policy.acceptedTcbStatuses,
  );
  return Object.freeze({
    ...(acceptedTcbStatuses !== undefined ? { acceptedTcbStatuses } : {}),
  });
}

function parseGatewayAttestationVerifiers(
  value: unknown,
): AttestationVerifiers {
  const verifiers = requireInputObject(value, 'verifiers');
  rejectUnknownInputKeys(verifiers, 'verifiers', ['quote', 'deployment']);

  const quote = optionalInputFunction(verifiers.quote, 'verifiers.quote');
  const deployment = optionalInputFunction(
    verifiers.deployment,
    'verifiers.deployment',
  );

  return Object.freeze({
    ...(quote !== undefined
      ? { quote: quote as AttestationVerifiers['quote'] }
      : {}),
    ...(deployment !== undefined
      ? { deployment: deployment as AttestationVerifiers['deployment'] }
      : {}),
  });
}
