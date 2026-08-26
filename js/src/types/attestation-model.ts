import type { AttestationEvidence } from './attestation-common';

/**
 * A model-serving report returned by the Cloud API only when queried with
 * `provider=near`. Its inherited TLS fingerprint, when present, is a
 * quote-bound server declaration rather than a client-observed model TLS
 * peer. It must not be used to parse third-party provider reports.
 */
export type ModelAttestation = AttestationEvidence & {
  /** Omitted for a CPU-only CVM; malformed present values are rejected. */
  nvidiaPayload?: string | null;
};
