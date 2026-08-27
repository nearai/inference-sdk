import type { AttestationEvidence } from './attestation-common';

/** Raw NEAR AI Cloud Gateway evidence. */
export type GatewayAttestation = AttestationEvidence & {
  reportedQuoteData: string;
};
