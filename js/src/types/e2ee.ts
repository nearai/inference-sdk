import type { VerifiedModelAttestation } from './verification';

export type PrepareE2eeChatRequestParams = {
  readonly request: Request;
  /** Successfully verified model evidence containing its quote-bound public key. */
  readonly attestation: VerifiedModelAttestation;
};

/** One encrypted request and the matching response decryption operation. */
export type PreparedE2eeChatRequest = {
  readonly request: Request;
  /** Decrypt JSON or SSE; unsuccessful HTTP responses pass through unchanged. */
  readonly decryptResponse: (response: Response) => Promise<Response>;
};
