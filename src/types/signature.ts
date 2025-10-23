export type ChatVerification = {
  isHashVerified: boolean;
  isSignatureVerified: boolean;
};

export type Chat = { requestBody: Buffer; responseBody: Buffer };

export type ChatSignature = {
  text: string;
  signature: string;
  signing_address: string;
  signing_algo: 'ecdsa' | 'ed25519';
};
