import type { AttestationEvidence } from './attestation-common';

/** Gateway evidence to verify against a peer observed on the same TLS connection. */
export type GatewayAttestation = AttestationEvidence & {
  reportedQuoteData: string;
};
