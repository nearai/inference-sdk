/** Signing algorithms exposed by NEAR AI Cloud. */
export type SigningAlgorithm = 'ecdsa' | 'ed25519';

/** Public identity of the key that signs a completion or attestation. */
export type SigningIdentity = {
  algorithm: SigningAlgorithm;
  address: string;
};

/** dstack event log as returned by the attestation endpoint. */
export type AttestationEventLog = string | readonly unknown[];

/** Shared raw evidence consumed by model and gateway verification. */
export type AttestationEvidence = {
  nonce: string;
  signer: SigningIdentity;
  intelQuote: string;
  eventLog: AttestationEventLog;
  appCompose: string;
  declaredSpkiFingerprint?: string | null;
  reportedQuoteData?: string;
};
