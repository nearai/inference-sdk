import type { CompletionSignature } from './chat';
import type { DirectAttestationClientOptions } from './direct-api';
import type { VerifiedDirectModelAttestation } from './direct-verification';
import type {
  InferenceClientCommonOptions,
  ModelVerificationOptions,
} from './inference-client';

export type DirectModelVerificationOptions = ModelVerificationOptions & {
  /** Browser Fetch cannot observe TLS certificates. Defaults to false. */
  readonly includeSpkiFingerprint?: false;
};

export type NodeDirectModelVerificationOptions = ModelVerificationOptions & {
  /** Request and verify model TLS evidence. Defaults to true. */
  readonly includeSpkiFingerprint?: boolean;
};

/** Verified Chat requests to one direct model endpoint, without a Gateway. */
export type DirectInferenceClientOptions = DirectAttestationClientOptions &
  Omit<InferenceClientCommonOptions, 'modelVerification'> & {
    readonly modelVerification?: DirectModelVerificationOptions;
  };

export type NodeDirectInferenceClientOptions = DirectAttestationClientOptions &
  Omit<InferenceClientCommonOptions, 'modelVerification'> & {
    readonly modelVerification?: NodeDirectModelVerificationOptions;
  };

export type VerifyDirectModelResponseParams = {
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
  readonly signature: CompletionSignature;
  readonly attestations: readonly VerifiedDirectModelAttestation[];
};

/** A signed response associated with the preflight-verified signer group. */
export type VerifiedDirectCompletionReceipt = {
  readonly completionId: string;
  readonly signatureKind: 'provider_tee';
  readonly signature: CompletionSignature;
  /** All verified reports sharing this signer, not a claim identifying one CVM. */
  readonly attestations: readonly VerifiedDirectModelAttestation[];
};
