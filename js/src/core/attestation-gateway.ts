import type {
  VerifiedGatewayAttestation,
  VerifyGatewayAttestationInput,
} from '../types/verification';
import {
  inputError,
  optionalInputObject,
  rejectUnknownInputKeys,
  requireInputFunction,
  requireInputObject,
  requireInputString,
} from '../utils/input';
import { verifyGatewayReportDataBinding } from './attestation-common';
import {
  requireAttestationEvidence,
  parseAttestationPolicy,
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
    signingAddress: attestation.signer.address,
    reportedSpkiFingerprint: attestation.declaredSpkiFingerprint,
    peerSpkiFingerprint,
  });
  const evidence = await verifyDstackDeployment(
    verifiedQuote,
    verifiers?.deployment,
  );

  return markVerifiedGatewayAttestation({ ...evidence, tlsBinding });
}

function parseGatewayAttestationInput(input: unknown): {
  attestation: VerifyGatewayAttestationInput['attestation'];
  nonce: string;
  peerSpkiFingerprint: string;
  policy: VerifyGatewayAttestationInput['policy'];
  verifiers: VerifyGatewayAttestationInput['verifiers'];
} {
  const record = requireInputObject(input, 'input');
  rejectUnknownInputKeys(record, 'input', [
    'attestation',
    'nonce',
    'peerSpkiFingerprint',
    'policy',
    'verifiers',
  ]);
  const attestation = requireAttestationEvidence(
    record.attestation,
  ) as VerifyGatewayAttestationInput['attestation'];
  if (typeof attestation.reportedQuoteData !== 'string') {
    throw inputError(
      'attestation.reportedQuoteData',
      attestation.reportedQuoteData === undefined
        ? 'missing'
        : 'unsupported_value',
      { expected: 'string' },
    );
  }
  return {
    attestation,
    nonce: requireInputString(record.nonce, 'nonce'),
    peerSpkiFingerprint: requireInputString(
      record.peerSpkiFingerprint,
      'peerSpkiFingerprint',
    ),
    policy: parseGatewayAttestationPolicy(record.policy),
    verifiers: parseGatewayAttestationVerifiers(record.verifiers),
  };
}

function parseGatewayAttestationPolicy(
  value: unknown,
): VerifyGatewayAttestationInput['policy'] {
  const policy = optionalInputObject(value, 'policy');
  if (!policy) {
    return undefined;
  }
  rejectUnknownInputKeys(policy, 'policy', ['acceptedTcbStatuses']);
  parseAttestationPolicy(policy);
  return policy as VerifyGatewayAttestationInput['policy'];
}

function parseGatewayAttestationVerifiers(
  value: unknown,
): VerifyGatewayAttestationInput['verifiers'] {
  const verifiers = optionalInputObject(value, 'verifiers');
  if (!verifiers) {
    return undefined;
  }
  rejectUnknownInputKeys(verifiers, 'verifiers', ['quote', 'deployment']);
  if (verifiers.quote !== undefined) {
    requireInputFunction(verifiers.quote, 'verifiers.quote');
  }
  if (verifiers.deployment !== undefined) {
    requireInputFunction(verifiers.deployment, 'verifiers.deployment');
  }
  return verifiers as VerifyGatewayAttestationInput['verifiers'];
}
