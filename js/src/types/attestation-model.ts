import type { AttestationEvidence } from './attestation-common';
import type { ComposeManagerAttestation } from './compose-manager';

/** Raw model-serving TEE evidence returned by NEAR AI Cloud. */
export type ModelAttestation = AttestationEvidence & {
  /** Quote-bound model public key used by the selected E2EE protocol, when provided. */
  signingPublicKey?: string;
  nvidiaPayload?: string;
  reportedQuoteData?: string;
  composeManagerAttestation?: ComposeManagerAttestation;
};
