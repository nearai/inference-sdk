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

/** A signature made by the model-serving TEE. */
export type ProviderTeeSignature = SignatureBase & {
  signature_kind: 'provider_tee';
};

/** A signature made by the Cloud API gateway, not by a model-serving TEE. */
export type GatewaySignature = SignatureBase & {
  signature_kind: 'gateway';
};

export type KnownChatSignature = ProviderTeeSignature | GatewaySignature;

/** A signature kind that this SDK does not recognize cannot support a claim. */
export type UnknownChatSignature = SignatureBase & {
  signature_kind?: string;
};

/** Provider response explaining why no usable signature is currently returned. */
export type SignatureUnavailable = {
  error_code: string;
  message: string;
};

/** Result of one signature lookup. The SDK does not poll automatically. */
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
