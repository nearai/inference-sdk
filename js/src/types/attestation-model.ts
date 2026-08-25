import { DstackAttestation } from './attestation-common';

/**
 * A model-serving report returned by the Cloud API only when queried with
 * `provider=near`. It must not be used to parse third-party provider reports.
 */
export type NearModelAttestation = DstackAttestation & {
  /** Omitted for a CPU-only CVM; malformed present values are rejected. */
  nvidia_payload?: string | null;
};
