import type { SigningIdentity } from './attestation-common';

/** Exact bytes sent to and received from the completion endpoint. */
export type CompletionBytes = {
  requestBody: Uint8Array;
  responseBody: Uint8Array;
};

/** What the Cloud API recorded about the signer of a completion signature. */
export type CompletionSignatureSource = 'model_tee' | 'gateway' | 'unknown';

/** A completion signature normalized from a NEAR AI Cloud response. */
export type CompletionSignature = {
  /** Exact payload text covered by `signature`. */
  signedText: string;
  signature: string;
  signer: SigningIdentity;
  /**
   * `unknown` represents a legacy record that did not store a source. It can
   * still establish a claim only after the corresponding response verifier
   * matches the complete signed payload and verified attestation identity.
   */
  source: CompletionSignatureSource;
};

/** Provider response explaining why no usable signature is currently returned. */
export type SignatureUnavailable = {
  errorCode: string;
  message: string;
};

/** Result of one signature lookup. The SDK does not poll automatically. */
export type CompletionSignatureLookup =
  | {
      status: 'found';
      signature: CompletionSignature;
    }
  | {
      status: 'unavailable';
      unavailable: SignatureUnavailable;
    };
