import type { AttestationEvidence } from './attestation-common';

/** Raw NEAR AI Cloud Gateway evidence. */
export type GatewayAttestation = AttestationEvidence & {
  /** TLS SPKI fingerprint declared by the Gateway and authenticated by its quote. */
  declaredSpkiFingerprint: string;
  reportedQuoteData: string;
};
