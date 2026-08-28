import type * as v from 'valibot';
import type {
  CloudApiGatewayAttestationSchema,
  CloudApiModelAttestationSchema,
} from '../schemas';
import type { SigningAlgo } from './attestation-common';
import type { GatewayAttestation } from './attestation-gateway';
import type { ModelAttestation } from './attestation-model';
import type { CompletionSignatureReference } from './chat';
import type { Awaitable } from './shared';

/**
 * Performs the request for Gateway attestation evidence and returns the TLS
 * peer observed for that exact request when the transport can expose it.
 */
export type GatewayAttestationTransport = (
  request: Request,
) => Awaitable<GatewayAttestationTransportResponse>;

export type GatewayAttestationTransportResponse = {
  readonly response: Response;
  /** SHA-256 SPKI fingerprint observed for this exact TLS peer, if available. */
  readonly peerSpkiFingerprint?: string;
};

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
  /** Optional TLS-aware transport for this Gateway attestation request. */
  readonly transport?: GatewayAttestationTransport;
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
export type FetchedGatewayAttestation =
  FetchedAttestation<GatewayAttestation> & {
    /** TLS peer observed by the optional transport for this exact request. */
    readonly peerSpkiFingerprint?: string;
  };
export type FetchedModelAttestations = {
  readonly attestations: readonly ModelAttestation[];
  /** Fresh client nonce sent with the request. */
  readonly nonce: string;
};
