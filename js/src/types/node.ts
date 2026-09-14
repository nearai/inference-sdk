/** Parameters for a Node HTTPS fetch pinned to an attested TLS SPKI. */
export type CreatePinnedTlsFetchParams = {
  /** SHA-256 SPKI fingerprint returned by verified Gateway evidence. */
  readonly spkiFingerprint: string;
};
