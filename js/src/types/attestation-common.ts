/** Algorithms emitted by NEAR AI attestation and signature endpoints. */
export type SigningAlgorithm = 'ecdsa' | 'ed25519';

/** A signing key advertised by an attestation or completion signature. */
export type SigningIdentity = {
  readonly algorithm: SigningAlgorithm;
  readonly address: string;
};

/** The dstack event log before its measurements have been verified. */
export type AttestationEventLog = string | readonly unknown[];

/**
 * Parsed evidence shared by model and gateway attestations. Obtain this from
 * `NearAiCloudClient` and pass it to the appropriate verifier unchanged.
 * Every field is untrusted until that verification succeeds.
 */
export type AttestationEvidence = {
  nonce: string;
  signer: SigningIdentity;
  intelQuote: string;
  eventLog: AttestationEventLog;
  /** Original compose text whose UTF-8 bytes are checked against MRCONFIGID. */
  appCompose: string;
  /** Server-declared SHA-256 SPKI fingerprint, when the report includes one. */
  declaredSpkiFingerprint?: string | null;
  /** Untrusted JSON copy of the Intel quote's report-data field, when supplied. */
  reportedQuoteData?: string;
};
