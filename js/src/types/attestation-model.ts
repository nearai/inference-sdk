import type { AttestationEvidence } from './attestation-common';

/** Raw model-serving TEE evidence returned by NEAR AI Cloud. */
export type ModelAttestation = AttestationEvidence & {
  nvidiaPayload?: string | null;
};
