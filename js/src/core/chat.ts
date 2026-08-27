import { Buffer } from 'buffer';
import { ethers } from 'ethers';
import nacl from 'tweetnacl';
import type { SigningAlgo, SigningIdentity } from '../types/attestation-common';
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

/**
 * Verify a model-serving signature over the exact completion bytes against the
 * signer in a caller-supplied model-attestation result.
 */
export function verifyModelResponse(input: VerifyModelResponseInput): void {
  const parsed = parseResponseInput(input);
  assertSignatureKind(parsed.signature, 'provider_tee');
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
 * Verify gateway-service provenance and integrity for the exact completion
 * bytes. The signature must match the signer in a caller-supplied
 * gateway-attestation result; this does not establish model execution.
 */
export function verifyGatewayResponse(input: VerifyGatewayResponseInput): void {
  const parsed = parseResponseInput(input);
  assertSignatureKind(parsed.signature, 'gateway');
  const expectedText = gatewaySignatureText(
    parsed.requestBody,
    parsed.responseBody,
  );
  verifySignatureTextAndBytes(parsed.signature, expectedText);
  verifySignatureMatchesAttestation(parsed.signature, parsed.attestation);
}

type ParsedResponseInput = {
  requestBody: Uint8Array;
  responseBody: Uint8Array;
  signature: CompletionSignature;
  attestation: { signer: SigningIdentity };
};

function parseResponseInput(input: unknown): ParsedResponseInput {
  const value = requireInputObject(input, 'input');
  rejectUnknownInputKeys(value, 'input', [
    'requestBody',
    'responseBody',
    'signature',
    'attestation',
  ]);

  const requestBody = requireInputBytes(value.requestBody, 'requestBody');
  const responseBody = requireInputBytes(value.responseBody, 'responseBody');
  const signature = parseCompletionSignature(value.signature);
  const attestationSigner = parseAttestationSigner(value.attestation);

  return {
    requestBody,
    responseBody,
    signature,
    attestation: {
      signer: attestationSigner,
    },
  };
}

function parseAttestationSigner(value: unknown): SigningIdentity {
  const attestation = requireInputObject(value, 'attestation');
  return parseSigningIdentity(attestation.signer, 'attestation.signer');
}

function parseCompletionSignature(value: unknown): CompletionSignature {
  const signature = requireInputObject(value, 'signature');
  rejectUnknownInputKeys(signature, 'signature', [
    'signedText',
    'signature',
    'signer',
    'kind',
  ]);

  return {
    signedText: requireInputString(
      signature.signedText,
      'signature.signedText',
    ),
    signature: requireInputString(signature.signature, 'signature.signature'),
    signer: parseSigningIdentity(signature.signer, 'signature.signer'),
    kind: requireSignatureKind(signature.kind, 'signature.kind'),
  };
}

function parseSigningIdentity(value: unknown, field: string): SigningIdentity {
  const signer = requireInputObject(value, field);
  rejectUnknownInputKeys(signer, field, ['signingAlgo', 'signingAddress']);

  return {
    signingAlgo: requireSigningAlgo(signer.signingAlgo, `${field}.signingAlgo`),
    signingAddress: requireInputString(
      signer.signingAddress,
      `${field}.signingAddress`,
    ),
  };
}

function requireSigningAlgo(value: unknown, field: string): SigningAlgo {
  if (value === 'ecdsa' || value === 'ed25519') {
    return value;
  }
  throw inputError(
    field,
    value === undefined ? 'missing' : 'unsupported_value',
    {
      expected: 'ecdsa or ed25519',
    },
  );
}

function requireSignatureKind(
  value: unknown,
  field: string,
): CompletionSignature['kind'] {
  if (value === 'provider_tee' || value === 'gateway') {
    return value;
  }
  throw inputError(
    field,
    value === undefined ? 'missing' : 'unsupported_value',
    {
      expected: 'provider_tee or gateway',
    },
  );
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

function assertSignatureKind(
  signature: CompletionSignature,
  expected: CompletionSignature['kind'],
): void {
  if (signature.kind !== expected) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.kind_mismatch',
      details: { expected, actual: signature.kind },
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
  attestation: { signer: SigningIdentity },
): void {
  if (
    signature.signer.signingAlgo !== attestation.signer.signingAlgo ||
    normalizeSigningAddress(signature.signer.signingAddress) !==
      normalizeVerifiedSigningAddress(attestation.signer.signingAddress)
  ) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.signer_mismatch',
    });
  }
}

function verifySignatureBytes(signature: CompletionSignature): void {
  if (signature.signer.signingAlgo === 'ecdsa') {
    const signatureBytes = parseSignatureHex(signature.signature, 'signature');
    const signingAddress = parseSignatureHex(
      signature.signer.signingAddress,
      'signer.signingAddress',
    );
    if (signatureBytes.length !== 65) {
      throw invalidSignatureLength('signature', 65, signatureBytes.length);
    }
    if (signingAddress.length !== 20) {
      throw invalidSignatureLength(
        'signer.signingAddress',
        20,
        signingAddress.length,
      );
    }

    let recoveredSigningAddress: string;
    try {
      recoveredSigningAddress = ethers.verifyMessage(
        signature.signedText,
        signature.signature,
      );
    } catch (cause) {
      throw invalidSignature('ecdsa', cause);
    }
    if (
      normalizeRecoveredSigningAddress(recoveredSigningAddress) !==
      normalizeSigningAddress(signature.signer.signingAddress)
    ) {
      throw new VerificationError({
        phase: 'signature',
        code: 'signature.invalid',
        details: { signingAlgo: 'ecdsa' },
      });
    }
    return;
  }

  if (signature.signer.signingAlgo === 'ed25519') {
    const publicKey = parseSignatureHex(
      signature.signer.signingAddress,
      'signer.signingAddress',
    );
    const signed = parseSignatureHex(signature.signature, 'signature');
    if (publicKey.length !== 32) {
      throw invalidSignatureLength(
        'signer.signingAddress',
        32,
        publicKey.length,
      );
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
        details: { signingAlgo: 'ed25519' },
      });
    }
    return;
  }

  throw new VerificationError({
    phase: 'signature',
    code: 'signature.format_invalid',
    details: {
      field: 'signer.signingAlgo',
      reason: 'unsupported_signing_algo',
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
  field: 'signature' | 'signer.signingAddress',
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
  field: 'signature' | 'signer.signingAddress',
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
  signingAlgo: SigningAlgo,
  cause: unknown,
): VerificationError {
  return new VerificationError(
    {
      phase: 'signature',
      code: 'signature.invalid',
      details: { signingAlgo },
    },
    { cause },
  );
}

function normalizeSigningAddress(signingAddress: string): string {
  return parseSignatureHex(signingAddress, 'signer.signingAddress').toString(
    'hex',
  );
}

function normalizeRecoveredSigningAddress(signingAddress: string): string {
  return parseSignatureHex(signingAddress, 'signer.signingAddress').toString(
    'hex',
  );
}

function normalizeVerifiedSigningAddress(signingAddress: string): string {
  try {
    return normalizeHex(signingAddress);
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
