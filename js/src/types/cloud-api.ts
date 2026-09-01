import type * as v from 'valibot';
import type {
  CloudApiGatewayAttestationSchema,
  CloudApiModelAttestationSchema,
} from '../schemas';
import type { SigningAlgo } from './attestation-common';
import type { GatewayAttestation } from './attestation-gateway';
import type { ModelAttestation } from './attestation-model';
import type { CompletionSignatureReference } from './chat';
import type {
  GatewayAttestationPolicy,
  GatewayClientBinding,
  ModelClientBinding,
} from './verification';

/** Configuration shared by all Cloud API evidence requests. */
export type AttestationClientOptions = {
  readonly apiKey: string;
  readonly baseUrl?: string;
};

export type FetchModelAttestationsParams = {
  readonly model: string;
  readonly signingAlgo?: SigningAlgo;
  readonly signingAddress?: string;
};

export type FetchModelAttestationForSignatureParams = {
  readonly model: string;
  readonly signature: CompletionSignatureReference;
};

export type FindModelAttestationForSignatureParams = {
  readonly attestations: readonly ModelAttestation[];
  readonly signature: CompletionSignatureReference;
};

export type FetchGatewayAttestationParams = {
  readonly signingAlgo?: SigningAlgo;
  /**
   * The policy returned with the fetched evidence. Its TLS setting controls
   * both the Cloud API request and the later quote binding check.
   */
  readonly policy?: GatewayAttestationPolicy;
};

export type FetchCompletionSignatureParams = {
  readonly completionId: string;
  readonly signingAlgo?: SigningAlgo;
};

export type LookupCompletionSignatureParams = {
  readonly completionId: string;
  readonly signingAlgo?: SigningAlgo;
};
export type CloudApiModelAttestation = v.InferOutput<
  typeof CloudApiModelAttestationSchema
>;
export type CloudApiGatewayAttestation = v.InferOutput<
  typeof CloudApiGatewayAttestationSchema
>;

export type FetchedModelAttestation = {
  readonly attestation: ModelAttestation;
  /** Client values associated with this model-attestation request. */
  readonly clientBinding: ModelClientBinding;
};

export type FetchedGatewayAttestation = {
  readonly attestation: GatewayAttestation;
  readonly clientBinding: GatewayClientBinding;
  /** Pass this object directly to `verifyGatewayAttestation`. */
  readonly policy: GatewayAttestationPolicy;
};
export type FetchedModelAttestations = {
  readonly attestations: readonly ModelAttestation[];
  /** Client values associated with this model-attestation request. */
  readonly clientBinding: ModelClientBinding;
};
