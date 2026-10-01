import type { CompletionSignature } from './chat';
import type { DirectAttestationClientOptions } from './direct-api';
import type {
  VerifiedDirectModelAttestation,
  VerifiedDirectModelAttestations,
} from './direct-verification';
import type {
  InferenceClientCommonOptions,
  InferenceEncryptionOptions,
  ModelVerificationOptions,
} from './inference-client';

export type DirectModelVerificationOptions = ModelVerificationOptions;

export type NodeDirectModelVerificationOptions = ModelVerificationOptions;

/**
 * Verified Chat requests to one direct model endpoint, without a Gateway.
 * @experimental Direct clients are not recommended for production.
 */
export type DirectInferenceClientOptions = DirectAttestationClientOptions &
  Omit<InferenceClientCommonOptions, 'modelVerification'> &
  InferenceEncryptionOptions & {
    readonly modelVerification?: DirectModelVerificationOptions;
  };

/** @experimental Options for the Node direct client, which is not recommended for production. */
export type NodeDirectInferenceClientOptions = DirectAttestationClientOptions &
  Omit<InferenceClientCommonOptions, 'modelVerification'> &
  InferenceEncryptionOptions & {
    readonly modelVerification?: NodeDirectModelVerificationOptions;
  };

export type VerifyDirectModelResponseParams = {
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
  readonly signature: CompletionSignature;
  readonly attestations: readonly VerifiedDirectModelAttestation[];
};

/** All verified direct reports and endpoint TLS binding, shared by verify() and Chat. */
export type DirectAttestationVerificationResult =
  VerifiedDirectModelAttestations & {
    /** Unix time in milliseconds when verification completed, unchanged on cache hits. */
    readonly verifiedAt: number;
  };

/** A signed response associated with the preflight-verified signer group. */
export type VerifiedDirectCompletionResult = {
  readonly id: string;
  readonly signatureKind: 'provider_tee';
  readonly signature: CompletionSignature;
  /** All verified reports sharing this signer, not a claim identifying one CVM. */
  readonly attestations: readonly VerifiedDirectModelAttestation[];
};
