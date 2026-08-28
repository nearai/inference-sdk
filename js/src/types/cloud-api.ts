import type * as v from 'valibot';
import type {
  CloudApiGatewayAttestationSchema,
  CloudApiModelAttestationSchema,
} from '../schemas';
import type { SigningAlgo } from './attestation-common';
import type { GatewayAttestation } from './attestation-gateway';
import type { ModelAttestation } from './attestation-model';
import type { CompletionSignatureReference } from './chat';
import type { GatewayClientBinding } from './verification';

export type FetchModelAttestationsParams = {
  readonly apiKey: string;
  readonly baseUrl?: string;
  readonly model: string;
  readonly signingAlgo?: SigningAlgo;
  readonly signingAddress?: string;
};

export type FetchModelAttestationForSignatureParams = {
  readonly apiKey: string;
  readonly baseUrl?: string;
  readonly model: string;
  readonly signature: CompletionSignatureReference;
};

export type FindModelAttestationForSignatureParams = {
  readonly attestations: readonly ModelAttestation[];
  readonly signature: CompletionSignatureReference;
};

export type FetchGatewayAttestationParams = {
  readonly apiKey: string;
  readonly baseUrl?: string;
  readonly signingAlgo?: SigningAlgo;
};

export type FetchCompletionSignatureParams = {
  readonly apiKey: string;
  readonly baseUrl?: string;
  readonly completionId: string;
  readonly signingAlgo?: SigningAlgo;
};

export type LookupCompletionSignatureParams = {
  readonly apiKey: string;
  readonly baseUrl?: string;
  readonly completionId: string;
  readonly signingAlgo?: SigningAlgo;
};
export type CloudApiModelAttestation = v.InferOutput<
  typeof CloudApiModelAttestationSchema
>;
export type CloudApiGatewayAttestation = v.InferOutput<
  typeof CloudApiGatewayAttestationSchema
>;

type FetchedAttestation<TAttestation> = {
  readonly attestation: TAttestation;
  /** Fresh client nonce sent with the request. */
  readonly nonce: string;
};

export type FetchedModelAttestation = FetchedAttestation<ModelAttestation>;
export type FetchedGatewayAttestation = {
  readonly attestation: GatewayAttestation;
  readonly clientBinding: GatewayClientBinding;
};
export type FetchedModelAttestations = {
  readonly attestations: readonly ModelAttestation[];
  /** Fresh client nonce sent with the request. */
  readonly nonce: string;
};
