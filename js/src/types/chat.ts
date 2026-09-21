import type { SigningIdentity } from './attestation-common';

export type CompletionSignatureKind = 'provider_tee' | 'gateway';

/** The signature identity needed to select matching model evidence. */
export type CompletionSignatureReference = {
  kind: CompletionSignatureKind;
  signer: SigningIdentity;
};

/** Completion signature normalized from a Gateway or direct endpoint response. */
export type CompletionSignature = CompletionSignatureReference & {
  signedText: string;
  signature: string;
};
