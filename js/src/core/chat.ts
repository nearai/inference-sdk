import { Buffer } from 'buffer';
import { ethers } from 'ethers';
import nacl from 'tweetnacl';
import type { SigningIdentity } from '../types/attestation-common';
import type { CompletionSignature } from '../types/chat';
import type {
  VerifyGatewayResponseInput,
  VerifyModelResponseInput,
} from '../types/verification';
import { hexToBuffer, normalizeHex } from '../utils/common';
import { VerificationError } from '../utils/errors';
import {
  inputError,
  rejectUnknownInputKeys,
  requireInputBytes,
  requireInputObject,
  requireInputString,
} from '../utils/input';
import {
  requireVerifiedGatewaySigner,
  requireVerifiedModelSigner,
} from './verified-attestation';

/**
 * Verify a model-serving signature over the exact completion bytes and bind it
 * to verified model evidence. Resolves only when the model-response claim is
 * valid. A legacy signature with an unknown source must still match the full
 * model payload, valid signature, and attested signer.
 */
export function verifyModelResponse(input: VerifyModelResponseInput): void {
  const parsed = parseResponseInput(input, requireVerifiedModelSigner);
  assertSignatureSource(parsed.signature, 'model_tee');
  const canonicalModelId = getCanonicalModelIdFromRequest(parsed.requestBody);
  const expectedText = modelSignatureText(
    canonicalModelId,
    parsed.requestBody,
    parsed.responseBody,
  );
  verifySignatureTextAndBytes(parsed.signature, expectedText);
  verifySignatureMatchesAttestation(parsed.signature, parsed.attestation);
}

/**
 * Verify a gateway signature over the exact completion bytes. Resolves only
 * when the gateway-response claim is valid; it does not establish model
 * execution. A legacy signature with an unknown source must still match the
 * full gateway payload, valid signature, and attested signer.
 */
export function verifyGatewayResponse(input: VerifyGatewayResponseInput): void {
  const parsed = parseResponseInput(input, requireVerifiedGatewaySigner);
  assertSignatureSource(parsed.signature, 'gateway');
  const expectedText = gatewaySignatureText(
    parsed.requestBody,
    parsed.responseBody,
  );
  verifySignatureTextAndBytes(parsed.signature, expectedText);
  verifySignatureMatchesAttestation(parsed.signature, parsed.attestation);
}

function parseResponseInput(
  input: unknown,
  requireVerifiedSigner: (attestation: unknown) => SigningIdentity,
): {
  requestBody: Uint8Array;
  responseBody: Uint8Array;
  signature: CompletionSignature;
  attestation: { signer: { algorithm: string; address: string } };
} {
  const record = requireInputObject(input, 'input');
  rejectUnknownInputKeys(record, 'input', [
    'requestBody',
    'responseBody',
    'signature',
    'attestation',
  ]);
  const signatureRecord = requireInputObject(record.signature, 'signature');
  rejectUnknownInputKeys(signatureRecord, 'signature', [
    'signedText',
    'signature',
    'signer',
    'source',
  ]);
  const signer = requireSigner(signatureRecord.signer, 'signature.signer');
  const source = requireInputString(signatureRecord.source, 'signature.source');
  if (source !== 'model_tee' && source !== 'gateway' && source !== 'unknown') {
    throw inputError('signature.source', 'unsupported_value', {
      expected: "'model_tee', 'gateway', or 'unknown'",
    });
  }
  const attestationSigner = requireVerifiedSigner(record.attestation);

  return {
    requestBody: requireInputBytes(record.requestBody, 'requestBody'),
    responseBody: requireInputBytes(record.responseBody, 'responseBody'),
    signature: {
      signedText: requireInputString(
        signatureRecord.signedText,
        'signature.signedText',
      ),
      signature: requireInputString(
        signatureRecord.signature,
        'signature.signature',
      ),
      signer,
      source,
    },
    attestation: {
      signer: attestationSigner,
    },
  };
}

function requireSigner(value: unknown, field: string): SigningIdentity {
  const signer = requireInputObject(value, field);
  rejectUnknownInputKeys(signer, field, ['algorithm', 'address']);
  const algorithm = requireInputString(signer.algorithm, `${field}.algorithm`);
  if (algorithm !== 'ecdsa' && algorithm !== 'ed25519') {
    throw inputError(`${field}.algorithm`, 'unsupported_value', {
      expected: "'ecdsa' or 'ed25519'",
    });
  }
  return {
    algorithm,
    address: requireInputString(signer.address, `${field}.address`),
  };
}

/** Internal test helper; normal users verify a complete response instead. */
export function modelSignatureText(
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

/** Internal test helper; normal users verify a complete response instead. */
export function gatewaySignatureText(
  requestBody: Uint8Array,
  responseBody: Uint8Array,
): string {
  return `${hashBytes(requestBody)}:${hashBytes(responseBody)}`;
}

function assertSignatureSource(
  signature: CompletionSignature,
  expected: 'model_tee' | 'gateway',
): void {
  if (signature.source !== 'unknown' && signature.source !== expected) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.source_mismatch',
      details: { expected, actual: signature.source },
    });
  }
}

function verifySignatureTextAndBytes(
  signature: CompletionSignature,
  expectedText: string,
): void {
  if (signature.signedText !== expectedText) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.payload_mismatch',
      details: { source: 'signed_payload', reason: 'text_mismatch' },
    });
  }
  verifySignatureBytes(signature);
}

function verifySignatureMatchesAttestation(
  signature: CompletionSignature,
  attestation: { signer: { algorithm: string; address: string } },
): void {
  if (
    signature.signer.algorithm !== attestation.signer.algorithm ||
    normalizeSignatureAddress(signature.signer.address) !==
      normalizeVerifiedSignerAddress(attestation.signer.address)
  ) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.signer_mismatch',
    });
  }
}

function verifySignatureBytes(signature: CompletionSignature): void {
  if (signature.signer.algorithm === 'ecdsa') {
    const signatureBytes = parseSignatureHex(signature.signature, 'signature');
    const address = parseSignatureHex(
      signature.signer.address,
      'signer.address',
    );
    if (signatureBytes.length !== 65) {
      throw invalidSignatureLength('signature', 65, signatureBytes.length);
    }
    if (address.length !== 20) {
      throw invalidSignatureLength('signer.address', 20, address.length);
    }

    let recovered: string;
    try {
      recovered = ethers.verifyMessage(
        signature.signedText,
        signature.signature,
      );
    } catch (cause) {
      throw invalidSignature('ecdsa', cause);
    }
    if (
      normalizeRecoveredAddress(recovered) !==
      normalizeSignatureAddress(signature.signer.address)
    ) {
      throw new VerificationError({
        phase: 'signature',
        code: 'signature.invalid',
        details: { algorithm: 'ecdsa' },
      });
    }
    return;
  }

  if (signature.signer.algorithm === 'ed25519') {
    const publicKey = parseSignatureHex(
      signature.signer.address,
      'signer.address',
    );
    const signed = parseSignatureHex(signature.signature, 'signature');
    if (publicKey.length !== 32) {
      throw invalidSignatureLength('signer.address', 32, publicKey.length);
    }
    if (signed.length !== 64) {
      throw invalidSignatureLength('signature', 64, signed.length);
    }
    let valid: boolean;
    try {
      valid = nacl.sign.detached.verify(
        Buffer.from(signature.signedText, 'utf8'),
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
      field: 'signer.algorithm',
      reason: 'unsupported_algorithm',
    },
  });
}

function hashBytes(value: Uint8Array): string {
  return ethers.sha256(value).slice(2);
}

/**
 * Model signatures identify the canonical model. To avoid silently treating
 * an alias as that identity, the verifier requires the exact raw completion
 * request to name that model. Use x-no-aliasing on the request.
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
  field: 'signature' | 'signer.address',
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
  field: 'signature' | 'signer.address',
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
  return parseSignatureHex(address, 'signer.address').toString('hex');
}

function normalizeRecoveredAddress(address: string): string {
  return parseSignatureHex(address, 'signer.address').toString('hex');
}

function normalizeVerifiedSignerAddress(address: string): string {
  try {
    return normalizeHex(address);
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'signature',
        code: 'signature.signer_mismatch',
      },
      { cause },
    );
  }
}
