import { SigningAlgo } from './attestation-common';

/** Exact bytes sent to and received from the completion endpoint. */
export type CompletionBytes = {
  requestBody: Uint8Array;
  responseBody: Uint8Array;
};

type SignatureBase = {
  text: string;
  signature: string;
  signing_address: string;
  signing_algo: SigningAlgo;
};

export type ProviderTeeSignature = SignatureBase & {
  signature_kind: 'provider_tee';
};

export type GatewaySignature = SignatureBase & {
  signature_kind: 'gateway';
};

export type KnownChatSignature = ProviderTeeSignature | GatewaySignature;

/** A historical or unknown signature kind cannot support a security claim. */
export type UnknownChatSignature = SignatureBase & {
  signature_kind?: string;
};

export type SignatureUnavailable = {
  error_code: string;
  message: string;
};

export type SignatureLookup =
  | {
      status: 'found';
      signature: KnownChatSignature;
    }
  | {
      status: 'unavailable';
      unavailable: SignatureUnavailable;
    }
  | {
      status: 'unknown_kind';
      signature: UnknownChatSignature;
    };
