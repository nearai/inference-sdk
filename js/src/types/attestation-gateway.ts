import type { AttestationEvidence } from './attestation-common';
import type { OhttpAttestation } from './ohttp';

/** Raw NEAR AI Cloud Gateway evidence. */
export type GatewayAttestation = AttestationEvidence & {
  /** Gateway-reported TLS SPKI fingerprint when the evidence request enables TLS binding. */
  spkiFingerprint?: string;
  reportedQuoteData: string;
  /** Signed OHTTP configuration from the report envelope; verify against this Gateway's authenticated signer. */
  ohttpAttestation?: OhttpAttestation;
};
