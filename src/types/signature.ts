import { Buffer } from 'buffer';

export type VerifyChatMessageParams = {
  requestBody: Buffer;
  responseBody: Buffer;
  signature: ChatMessageSignature;
};

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
