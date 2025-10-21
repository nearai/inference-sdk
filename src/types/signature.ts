export type ChatMessageVerification = {
  isHashVerified: boolean;
  isSignatureVerified: boolean;
};

export type ChatMessage = { requestBody: Buffer; responseBody: Buffer };

export type ChatMessageSignature = {
  text: string;
  signature: string;
  signing_address: string;
  signing_algo: 'ecdsa' | 'ed25519';
};
