/** Parameters for a Node HTTPS fetch pinned to an attested Gateway SPKI. */
export type CreatePinnedGatewayFetchParams = {
  /** SHA-256 SPKI fingerprint returned by verified Gateway evidence. */
  readonly spkiFingerprint: string;
};
