import type { AttestationEvidence } from './attestation-common';

/** Raw NEAR AI Cloud Gateway evidence. */
export type GatewayAttestation = AttestationEvidence & {
  /** TLS SPKI fingerprint returned when the evidence request enables TLS binding. */
  tlsSpkiFingerprint?: string;
  reportedQuoteData: string;
};
