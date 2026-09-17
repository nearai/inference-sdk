import type { SigningAlgo } from './attestation-common';

/** Model public key and signing algorithm used by the E2EE protocol. */
export type E2eeModelKey = {
  readonly signingAlgo: SigningAlgo;
  /** Hexadecimal model public key, obtained from verified attestation evidence. */
  readonly publicKey: string;
};

export type PrepareE2eeChatRequestParams = {
  readonly request: Request;
  readonly modelKey: E2eeModelKey;
};

/** One encrypted request and the matching response decryption operation. */
export type PreparedE2eeChatRequest = {
  readonly request: Request;
  /** Decrypt JSON or SSE; unsuccessful HTTP responses pass through unchanged. */
  readonly decryptResponse: (response: Response) => Promise<Response>;
};
