export type Chat = { requestBody: Buffer; responseBody: Buffer };

export type ChatSignature = {
  text: string;
  signature: string;
  signing_address: string;
  signing_algo: SigningAlgo;
};

export type SigningAlgo = 'ecdsa' | 'ed25519';
