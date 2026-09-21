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

/** The serving attestation and complete serving set supplied by a direct endpoint. */
export type DirectModelAttestations = {
  /** The top-level attestation returned by the endpoint serving this request. Also an entry in `attestations`. */
  readonly servingAttestation: DirectModelAttestation;
  readonly attestations: readonly DirectModelAttestation[];
};

/** Client nonce and optional TLS peer evidence supplied to direct verification. */
export type DirectClientBinding = {
  readonly nonce: string;
  readonly spkiFingerprint?: string;
};

export type FetchedDirectModelAttestations = DirectModelAttestations & {
  readonly clientBinding: DirectClientBinding;
};

export type DirectAttestationClientOptions = {
  /** Provider API base URL, including its version path (for example /v1). */
  readonly baseUrl: string;
  readonly apiKey?: string;
  readonly headers?: HeadersInit;
};

export type FetchDirectModelAttestationsParams = {
  readonly signingAlgo?: SigningAlgo;
  readonly signingAddress?: string;
};

export type NodeFetchDirectModelAttestationsParams =
  FetchDirectModelAttestationsParams;

export type DirectApiModelAttestation = v.InferOutput<
  typeof DirectApiModelAttestationSchema
>;
export type DirectApiAttestationReport = v.InferOutput<
  typeof DirectApiAttestationReportSchema
>;
export type DirectApiCompletionSignatureResult = v.InferOutput<
  typeof DirectApiCompletionSignatureResultSchema
>;
