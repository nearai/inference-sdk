import { SigningAlgo } from './attestation-common';

export type Chat = { requestBody: Buffer; responseBody: Buffer };

export type ChatSignature = {
  text: string;
  signature: string;
  signing_address: string;
  signing_algo: SigningAlgo;
};
