import { ethers } from 'ethers';
import nacl from 'tweetnacl';
import {
  GatewaySignature,
  KnownChatSignature,
  ProviderTeeSignature,
  SignatureLookup,
} from '../types/chat';
import {
  VerifiedResponseSignature,
  VerifyGatewayResponseInput,
  VerifyProviderTeeResponseInput,
} from '../types/verification';
import { hexToBuffer, normalizeHex } from '../utils/common';
import { VerificationError } from '../utils/errors';
import sha256 from 'sha256';

/** Build the exact text signed by a model-serving TEE. */
export function providerTeeSignatureText(
  canonicalModelId: string,
  requestBody: Uint8Array,
  responseBody: Uint8Array,
): string {
  if (!canonicalModelId) {
    throw new VerificationError(
      'canonicalModelId is required for provider_tee',
    );
  }
  return `${canonicalModelId}:${hashBytes(requestBody)}:${hashBytes(responseBody)}`;
}

/** Build the exact text signed by the Cloud API gateway TEE. */
export function gatewaySignatureText(
  requestBody: Uint8Array,
  responseBody: Uint8Array,
): string {
  return `${hashBytes(requestBody)}:${hashBytes(responseBody)}`;
}

/**
 * Verify a `provider_tee` signature and bind it to verified NEAR model
 * evidence. This is the only response verification result with model scope.
 */
export function verifyProviderTeeResponse(
  input: VerifyProviderTeeResponseInput,
): VerifiedResponseSignature {
  const canonicalModelId = getCanonicalModelIdFromRequest(input.requestBody);
  const expectedText = providerTeeSignatureText(
    canonicalModelId,
    input.requestBody,
    input.responseBody,
  );
  verifySignatureTextAndBytes(input.signature, expectedText);
  verifySignatureMatchesAttestation(
    input.signature,
    input.verifiedModelAttestation,
  );
  return {
    scope: 'model_tee',
    signingAddress: input.signature.signing_address,
    signingAlgo: input.signature.signing_algo,
  };
}

/**
 * Verify a `gateway` signature. Its success does not establish that a model
 * TEE produced the response.
 */
export function verifyGatewayResponse(
  input: VerifyGatewayResponseInput,
): VerifiedResponseSignature {
  const expectedText = gatewaySignatureText(
    input.requestBody,
    input.responseBody,
  );
  verifySignatureTextAndBytes(input.signature, expectedText);
  verifySignatureMatchesAttestation(
    input.signature,
    input.verifiedGatewayAttestation,
  );
  return {
    scope: 'gateway',
    signingAddress: input.signature.signing_address,
    signingAlgo: input.signature.signing_algo,
  };
}

/** Reject unavailable, historical, and unknown signature kinds explicitly. */
export function requireKnownSignature(
  lookup: SignatureLookup,
): KnownChatSignature {
  if (lookup.status === 'unavailable') {
    throw new VerificationError(
      `Completion signature is unavailable: ${lookup.unavailable.error_code}`,
    );
  }
  if (lookup.status === 'unknown_kind') {
    throw new VerificationError(
      'Completion signature kind is missing or unsupported; no verification claim can be made',
    );
  }
  return lookup.signature;
}

function verifySignatureTextAndBytes(
  signature: KnownChatSignature,
  expectedText: string,
): void {
  if (signature.text !== expectedText) {
    throw new VerificationError(
      'Signature text does not match the exact response bytes',
    );
  }
  verifySignatureBytes(signature);
}

function verifySignatureMatchesAttestation(
  signature: KnownChatSignature,
  attestation: {
    signingAddress: string;
    signingAlgo: string;
  },
): void {
  if (
    signature.signing_algo !== attestation.signingAlgo ||
    normalizeHex(signature.signing_address) !==
      normalizeHex(attestation.signingAddress)
  ) {
    throw new VerificationError(
      'Signature signer does not match the verified attestation signer',
    );
  }
}

function verifySignatureBytes(signature: KnownChatSignature): void {
  if (signature.signing_algo === 'ecdsa') {
    const signatureBytes = hexToBuffer(signature.signature);
    const address = hexToBuffer(signature.signing_address);
    if (signatureBytes.length !== 65) {
      throw new VerificationError('ECDSA signature must be 65 bytes');
    }
    if (address.length !== 20) {
      throw new VerificationError('ECDSA signing_address must be 20 bytes');
    }

    let recovered: string;
    try {
      recovered = ethers.verifyMessage(signature.text, signature.signature);
    } catch (cause) {
      throw new VerificationError('Invalid ECDSA completion signature', cause);
    }
    if (normalizeHex(recovered) !== normalizeHex(signature.signing_address)) {
      throw new VerificationError(
        'ECDSA signature recovered a different address',
      );
    }
    return;
  }

  if (signature.signing_algo === 'ed25519') {
    const publicKey = hexToBuffer(signature.signing_address);
    const signed = hexToBuffer(signature.signature);
    if (publicKey.length !== 32) {
      throw new VerificationError('Ed25519 signing_address must be 32 bytes');
    }
    if (signed.length !== 64) {
      throw new VerificationError('Ed25519 signature must be 64 bytes');
    }
    if (
      !nacl.sign.detached.verify(
        Buffer.from(signature.text, 'utf8'),
        signed,
        publicKey,
      )
    ) {
      throw new VerificationError('Invalid Ed25519 completion signature');
    }
    return;
  }

  throw new VerificationError('Unsupported completion signing algorithm');
}

function hashBytes(value: Uint8Array): string {
  return sha256(Buffer.from(value));
}

/**
 * Provider signatures identify the canonical model. To avoid silently treating
 * an alias as that identity, the high-level verifier requires the exact raw
 * completion request to name that model. Use x-no-aliasing on the request.
 */
function getCanonicalModelIdFromRequest(requestBody: Uint8Array): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(requestBody).toString('utf8'));
  } catch (cause) {
    throw new VerificationError(
      'provider_tee verification requires a JSON request with a canonical model field',
      cause,
    );
  }
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    typeof (parsed as Record<string, unknown>).model !== 'string' ||
    !(parsed as Record<string, string>).model
  ) {
    throw new VerificationError(
      'provider_tee verification requires a non-empty canonical request model',
    );
  }
  return (parsed as Record<string, string>).model;
}

export type { GatewaySignature, ProviderTeeSignature };
