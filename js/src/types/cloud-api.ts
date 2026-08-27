import type * as v from 'valibot';
import type {
  CloudApiAttestationInfoEnvelopeSchema,
  CloudApiCompletionSignatureResponseSchema,
  CloudApiGatewayAttestationResponseSchema,
  CloudApiGatewayAttestationSchema,
  CloudApiInfoSchema,
  CloudApiModelAttestationResponseSchema,
  CloudApiModelAttestationSchema,
  CloudApiTcbInfoSchema,
  CloudApiUnavailableSignatureResponseSchema,
  ResponseLikeSchema,
} from '../schemas';
import type { SigningAlgo } from './attestation-common';
import type { GatewayAttestation } from './attestation-gateway';
import type { ModelAttestation } from './attestation-model';
import type { CompletionSignatureReference } from './chat';
import type { Awaitable } from './shared';

export type NearAiCloudFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Awaitable<Response>;

/** Transport configuration shared by NEAR AI Cloud fetch helpers. */
export type NearAiCloudOptions = {
  readonly apiKey: string;
  readonly baseUrl?: string;
  readonly fetch?: NearAiCloudFetch;
};

export type FetchModelAttestationsInput = {
  readonly model: string;
  readonly signingAlgo?: SigningAlgo;
  readonly signingAddress?: string;
};

export type FetchModelAttestationForSignatureInput = {
  readonly model: string;
  readonly signature: CompletionSignatureReference;
};

export type FindModelAttestationForSignatureInput = {
  readonly attestations: readonly ModelAttestation[];
  readonly signature: CompletionSignatureReference;
};

export type FetchGatewayAttestationInput = {
  readonly signingAlgo?: SigningAlgo;
};

export type FetchCompletionSignatureInput = {
  readonly completionId: string;
  readonly signingAlgo?: SigningAlgo;
};
export type ResponseLike = v.InferOutput<typeof ResponseLikeSchema>;

export type CloudApiTcbInfo = v.InferOutput<typeof CloudApiTcbInfoSchema>;
export type CloudApiInfo = v.InferOutput<typeof CloudApiInfoSchema>;
export type CloudApiAttestationInfoEnvelope = v.InferOutput<
  typeof CloudApiAttestationInfoEnvelopeSchema
>;
export type CloudApiModelAttestation = v.InferOutput<
  typeof CloudApiModelAttestationSchema
>;
export type CloudApiGatewayAttestation = v.InferOutput<
  typeof CloudApiGatewayAttestationSchema
>;
export type CloudApiModelAttestationResponse = v.InferOutput<
  typeof CloudApiModelAttestationResponseSchema
>;
export type CloudApiGatewayAttestationResponse = v.InferOutput<
  typeof CloudApiGatewayAttestationResponseSchema
>;
export type CloudApiUnavailableSignatureResponse = v.InferOutput<
  typeof CloudApiUnavailableSignatureResponseSchema
>;
export type CloudApiCompletionSignatureResponse = v.InferOutput<
  typeof CloudApiCompletionSignatureResponseSchema
>;

type FetchedAttestation<TAttestation> = {
  readonly attestation: TAttestation;
  /** Fresh client nonce sent with the request. */
  readonly nonce: string;
};

export type FetchedModelAttestation = FetchedAttestation<ModelAttestation>;
export type FetchedGatewayAttestation = FetchedAttestation<GatewayAttestation>;
export type FetchedModelAttestations = {
  readonly attestations: readonly ModelAttestation[];
  /** Fresh client nonce sent with the request. */
  readonly nonce: string;
};
