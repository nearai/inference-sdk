import type * as v from 'valibot';
import type {
  DirectApiAttestationReportSchema,
  DirectApiCompletionSignatureResultSchema,
  DirectApiModelAttestationSchema,
} from '../schemas';
import type { SigningAlgo } from './attestation-common';
import type { ModelAttestation } from './attestation-model';

/** Model evidence returned directly by a provider, without a Cloud envelope. */
export type DirectModelAttestation = ModelAttestation & {
  readonly modelName: string;
  readonly instanceId?: string;
  readonly spkiFingerprint?: string;
};

/** The top-level report and every entry supplied in all_attestations. */
export type DirectAttestationReport = {
  readonly attestation: DirectModelAttestation;
  readonly attestations: readonly DirectModelAttestation[];
  /** Opaque Compose Manager evidence; not verified by model verification. */
  readonly composeManagerAttestation?: unknown;
};

/** Locally generated nonce and, in Node, the observed TLS peer SPKI hash. */
export type DirectClientBinding = {
  readonly nonce: string;
  readonly spkiFingerprint?: string;
};

export type FetchedDirectAttestationReport = {
  readonly report: DirectAttestationReport;
  readonly clientBinding: DirectClientBinding;
};

export type DirectAttestationClientOptions = {
  /** Provider API base URL, including its version path (for example /v1). */
  readonly baseUrl: string;
  readonly apiKey?: string;
  readonly headers?: HeadersInit;
};

export type FetchDirectAttestationReportParams = {
  readonly signingAlgo?: SigningAlgo;
  readonly signingAddress?: string;
  /** Standard Fetch cannot observe the TLS peer certificate. */
  readonly includeSpkiFingerprint?: false;
};

export type NodeFetchDirectAttestationReportParams = {
  readonly signingAlgo?: SigningAlgo;
  readonly signingAddress?: string;
  readonly includeSpkiFingerprint?: boolean;
};

export type DirectApiModelAttestation = v.InferOutput<
  typeof DirectApiModelAttestationSchema
>;
export type DirectApiAttestationReport = v.InferOutput<
  typeof DirectApiAttestationReportSchema
>;
export type DirectApiCompletionSignatureResult = v.InferOutput<
  typeof DirectApiCompletionSignatureResultSchema
>;
