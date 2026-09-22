import type { AttestationEvidence } from './attestation-common';
import type { ChutesModelAttestation } from './attestation-chutes';

/** Raw evidence from NEAR AI's own model-serving TEE fleet. */
export type NearModelAttestation = AttestationEvidence & {
  readonly provider: 'near';
  /** Quote-bound model public key used by the selected E2EE protocol, when provided. */
  signingPublicKey?: string;
  nvidiaPayload?: string;
  reportedQuoteData?: string;
};

/** Provider-specific model-serving TEE evidence returned by NEAR AI Cloud. */
export type ModelAttestation = NearModelAttestation | ChutesModelAttestation;
