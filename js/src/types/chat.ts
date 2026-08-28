import type { SigningIdentity } from './attestation-common';

export type CompletionSignatureKind = 'provider_tee' | 'gateway';

/** The signature identity needed to select matching model evidence. */
export type CompletionSignatureReference = {
  kind: CompletionSignatureKind;
  signer: SigningIdentity;
};

/** Completion signature normalized from the Cloud API wire response. */
export type CompletionSignature = CompletionSignatureReference & {
  signedText: string;
  signature: string;
};

/** Service-reported reason that a completion signature is not available yet. */
export type SignatureUnavailable = {
  errorCode: string;
  message: string;
};

/** Result of looking up a completion signature without turning unavailability into an error. */
export type CompletionSignatureLookup =
  | { status: 'found'; signature: CompletionSignature }
  | { status: 'unavailable'; unavailable: SignatureUnavailable };
