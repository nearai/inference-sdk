export type ChatMessageVerification = {
  isHashMatched: boolean;
  isSignatureVerified: boolean;
};

export type ChatMessageSignature = {
  text: string;
  signature: string;
  signing_address: string;
  signing_algo: SigningAlgo;
};

export type SigningAlgo = 'ecdsa' | 'ed25519';
