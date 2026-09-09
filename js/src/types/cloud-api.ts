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
  GatewayClientBinding,
  ModelClientBinding,
  VerifiedModelAttestation,
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

export type FindModelAttestationForSignatureParams = {
  /** Successful results returned by `verifyModelAttestation`. */
  readonly attestations: readonly VerifiedModelAttestation[];
  readonly signature: CompletionSignatureReference;
};

export type FetchGatewayAttestationParams = {
  readonly signingAlgo?: SigningAlgo;
  /**
   * The generic client cannot observe the TLS peer certificate, so this may
   * only be disabled. It defaults to `false`.
   */
  readonly includeSpkiFingerprint?: false;
};

/** Gateway-attestation options supported by the Node-specific client. */
export type NodeFetchGatewayAttestationParams = {
  readonly signingAlgo?: SigningAlgo;
  /**
   * Request a TLS SPKI fingerprint in the Gateway attestation. Defaults to
   * `true`; the Node client captures the matching peer fingerprint.
   */
  readonly includeSpkiFingerprint?: boolean;
};

export type FetchCompletionSignatureParams = {
  readonly completionId: string;
  readonly signingAlgo?: SigningAlgo;
};
export type CloudApiModelAttestation = v.InferOutput<
  typeof CloudApiModelAttestationSchema
>;
export type CloudApiGatewayAttestation = v.InferOutput<
  typeof CloudApiGatewayAttestationSchema
>;

export type FetchedGatewayAttestation = {
  readonly attestation: GatewayAttestation;
  readonly clientBinding: GatewayClientBinding;
};
export type FetchedModelAttestations = {
  readonly attestations: readonly ModelAttestation[];
  /** Client values associated with this model-attestation request. */
  readonly clientBinding: ModelClientBinding;
};
