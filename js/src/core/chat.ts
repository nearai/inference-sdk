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

/**
 * Build the exact model-serving TEE payload:
 * `<canonical-model>:sha256(request-bytes):sha256(response-bytes)`.
 */
export function providerTeeSignatureText(
  canonicalModelId: string,
  requestBody: Uint8Array,
  responseBody: Uint8Array,
): string {
  if (!canonicalModelId) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.payload_mismatch',
      details: { source: 'request_model', reason: 'missing_model' },
    });
  }
  return `${canonicalModelId}:${hashBytes(requestBody)}:${hashBytes(responseBody)}`;
}

/**
 * Build the exact Cloud API gateway payload:
 * `sha256(request-bytes):sha256(response-bytes)`.
 */
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

/**
 * Narrow a successful lookup to an SDK-recognized signature. This does not
 * establish model execution by itself: callers must still require
 * `signature_kind === 'provider_tee'` before calling the model verifier.
 */
export function requireKnownSignature(
  lookup: SignatureLookup,
): KnownChatSignature {
  if (lookup.status === 'unavailable') {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.unavailable',
      details: { providerErrorCode: lookup.unavailable.error_code },
    });
  }
  if (lookup.status === 'unknown_kind') {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.unknown_kind',
      details: {},
    });
  }
  return lookup.signature;
}

function verifySignatureTextAndBytes(
  signature: KnownChatSignature,
  expectedText: string,
): void {
  if (signature.text !== expectedText) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.payload_mismatch',
      details: { source: 'signed_payload', reason: 'text_mismatch' },
    });
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
    normalizeSignatureAddress(signature.signing_address) !==
      normalizeVerifiedSignerAddress(attestation.signingAddress)
  ) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.signer_mismatch',
      details: {},
    });
  }
}

function verifySignatureBytes(signature: KnownChatSignature): void {
  if (signature.signing_algo === 'ecdsa') {
    const signatureBytes = parseSignatureHex(signature.signature, 'signature');
    const address = parseSignatureHex(
      signature.signing_address,
      'signing_address',
    );
    if (signatureBytes.length !== 65) {
      throw invalidSignatureLength('signature', 65, signatureBytes.length);
    }
    if (address.length !== 20) {
      throw invalidSignatureLength('signing_address', 20, address.length);
    }

    let recovered: string;
    try {
      recovered = ethers.verifyMessage(signature.text, signature.signature);
    } catch (cause) {
      throw invalidSignature('ecdsa', cause);
    }
    if (
      normalizeRecoveredAddress(recovered) !==
      normalizeSignatureAddress(signature.signing_address)
    ) {
      throw new VerificationError({
        phase: 'signature',
        code: 'signature.invalid',
        details: { algorithm: 'ecdsa' },
      });
    }
    return;
  }

  if (signature.signing_algo === 'ed25519') {
    const publicKey = parseSignatureHex(
      signature.signing_address,
      'signing_address',
    );
    const signed = parseSignatureHex(signature.signature, 'signature');
    if (publicKey.length !== 32) {
      throw invalidSignatureLength('signing_address', 32, publicKey.length);
    }
    if (signed.length !== 64) {
      throw invalidSignatureLength('signature', 64, signed.length);
    }
    let valid: boolean;
    try {
      valid = nacl.sign.detached.verify(
        Buffer.from(signature.text, 'utf8'),
        signed,
        publicKey,
      );
    } catch (cause) {
      throw invalidSignature('ed25519', cause);
    }
    if (!valid) {
      throw new VerificationError({
        phase: 'signature',
        code: 'signature.invalid',
        details: { algorithm: 'ed25519' },
      });
    }
    return;
  }

  throw new VerificationError({
    phase: 'signature',
    code: 'signature.format_invalid',
    details: {
      field: 'signing_algo',
      reason: 'unsupported_algorithm',
    },
  });
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
      {
        phase: 'signature',
        code: 'signature.payload_mismatch',
        details: { source: 'request_model', reason: 'invalid_json' },
      },
      { cause },
    );
  }
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    typeof (parsed as Record<string, unknown>).model !== 'string' ||
    !(parsed as Record<string, string>).model
  ) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.payload_mismatch',
      details: { source: 'request_model', reason: 'missing_model' },
    });
  }
  return (parsed as Record<string, string>).model;
}

function parseSignatureHex(
  value: string,
  field: 'signature' | 'signing_address',
): Buffer {
  try {
    return hexToBuffer(value);
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'signature',
        code: 'signature.format_invalid',
        details: { field, reason: 'invalid_hex' },
      },
      { cause },
    );
  }
}

function invalidSignatureLength(
  field: 'signature' | 'signing_address',
  expectedBytes: number,
  actualBytes: number,
): VerificationError {
  return new VerificationError({
    phase: 'signature',
    code: 'signature.format_invalid',
    details: { field, reason: 'wrong_length', expectedBytes, actualBytes },
  });
}

function invalidSignature(
  algorithm: 'ecdsa' | 'ed25519',
  cause: unknown,
): VerificationError {
  return new VerificationError(
    {
      phase: 'signature',
      code: 'signature.invalid',
      details: { algorithm },
    },
    { cause },
  );
}

function normalizeSignatureAddress(address: string): string {
  return parseSignatureHex(address, 'signing_address').toString('hex');
}

function normalizeRecoveredAddress(address: string): string {
  return parseSignatureHex(address, 'signing_address').toString('hex');
}

function normalizeVerifiedSignerAddress(address: string): string {
  try {
    return normalizeHex(address);
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'signature',
        code: 'signature.signer_mismatch',
        details: {},
      },
      { cause },
    );
  }
}

export type { GatewaySignature, ProviderTeeSignature };
