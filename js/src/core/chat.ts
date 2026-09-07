import { Buffer } from 'buffer';
import { ethers } from 'ethers';
import nacl from 'tweetnacl';
import * as v from 'valibot';
import { CompletionRequestModelSchema } from '../schemas';
import type { SigningAlgo, SigningIdentity } from '../types/attestation-common';
import type { CompletionSignature } from '../types/chat';
import type {
  VerifyGatewayResponseParams,
  VerifyModelResponseParams,
} from '../types/verification';
import { hexToBuffer } from '../utils/common';
import { VerificationError } from '../utils/errors';

/**
 * Verify a model-serving signature over the exact completion bytes against the
 * signer in a caller-supplied model-attestation result.
 */
export function verifyModelResponse({
  requestBody,
  responseBody,
  signature,
  attestation,
}: VerifyModelResponseParams): void {
  assertSignatureKind(signature, 'provider_tee');
  const canonicalModelId = getCanonicalModelIdFromRequest(requestBody);
  const expectedText = modelSignatureText({
    canonicalModelId,
    requestBody,
    responseBody,
  });
  verifySignatureTextAndBytes(signature, expectedText);
  verifySignatureMatchesAttestation(signature, attestation);
}

/**
 * Verify gateway-service provenance and integrity for the exact completion
 * bytes. The signature must match the signer in a caller-supplied
 * gateway-attestation result; this does not establish model execution.
 */
export function verifyGatewayResponse({
  requestBody,
  responseBody,
  signature,
  attestation,
}: VerifyGatewayResponseParams): void {
  assertSignatureKind(signature, 'gateway');
  const expectedText = gatewaySignatureText(requestBody, responseBody);
  verifySignatureTextAndBytes(signature, expectedText);
  verifySignatureMatchesAttestation(signature, attestation);
}

type SigningAttestation = {
  signer: SigningIdentity;
};

type ModelSignatureTextParams = {
  canonicalModelId: string;
  requestBody: Uint8Array;
  responseBody: Uint8Array;
};
type InvalidSignatureLengthParams = {
  field: 'signature' | 'signer.signingAddress';
  expectedBytes: number;
  actualBytes: number;
};

function modelSignatureText({
  canonicalModelId,
  requestBody,
  responseBody,
}: ModelSignatureTextParams): string {
  return `${canonicalModelId}:${hashBytes(requestBody)}:${hashBytes(responseBody)}`;
}

function gatewaySignatureText(
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
      code: 'signature.payload_mismatch',
      details: { source: 'signed_payload', reason: 'text_mismatch' },
    });
  }
  verifySignatureBytes(signature);
}

function verifySignatureMatchesAttestation(
  signature: CompletionSignature,
  attestation: SigningAttestation,
): void {
  if (signature.signer.signingAlgo !== attestation.signer.signingAlgo) {
    throw new VerificationError({
      code: 'signature.signer_mismatch',
    });
  }

  const signatureSigningAddress = parseSignatureHex(
    signature.signer.signingAddress,
    'signer.signingAddress',
  );
  const attestationSigningAddress = hexToBuffer(
    attestation.signer.signingAddress,
  );
  if (!signatureSigningAddress.equals(attestationSigningAddress)) {
    throw new VerificationError({
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
      throw invalidSignatureLength({
        field: 'signature',
        expectedBytes: 65,
        actualBytes: signatureBytes.length,
      });
    }
    if (signingAddress.length !== 20) {
      throw invalidSignatureLength({
        field: 'signer.signingAddress',
        expectedBytes: 20,
        actualBytes: signingAddress.length,
      });
    }

    let recoveredSigningAddress: string;
    try {
      recoveredSigningAddress = ethers.verifyMessage(
        signature.signedText,
        ethers.hexlify(signatureBytes),
      );
    } catch (cause) {
      throw invalidSignature('ecdsa', cause);
    }
    if (
      !parseSignatureHex(
        recoveredSigningAddress,
        'signer.signingAddress',
      ).equals(signingAddress)
    ) {
      throw new VerificationError({
        code: 'signature.invalid',
        details: { signingAlgo: 'ecdsa' },
      });
    }
    return;
  }

  const publicKey = parseSignatureHex(
    signature.signer.signingAddress,
    'signer.signingAddress',
  );
  const signed = parseSignatureHex(signature.signature, 'signature');
  if (publicKey.length !== 32) {
    throw invalidSignatureLength({
      field: 'signer.signingAddress',
      expectedBytes: 32,
      actualBytes: publicKey.length,
    });
  }
  if (signed.length !== 64) {
    throw invalidSignatureLength({
      field: 'signature',
      expectedBytes: 64,
      actualBytes: signed.length,
    });
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
      code: 'signature.invalid',
      details: { signingAlgo: 'ed25519' },
    });
  }
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
  let request: unknown;
  try {
    request = JSON.parse(Buffer.from(requestBody).toString('utf8'));
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'signature.payload_mismatch',
        details: { source: 'request_model', reason: 'invalid_json' },
      },
      { cause },
    );
  }
  const parsed = v.safeParse(CompletionRequestModelSchema, request);
  if (!parsed.success) {
    throw new VerificationError({
      code: 'signature.payload_mismatch',
      details: { source: 'request_model', reason: 'missing_model' },
    });
  }
  return parsed.output.model;
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
        code: 'signature.format_invalid',
        details: { field, reason: 'invalid_hex' },
      },
      { cause },
    );
  }
}

function invalidSignatureLength({
  field,
  expectedBytes,
  actualBytes,
}: InvalidSignatureLengthParams): VerificationError {
  return new VerificationError({
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
      code: 'signature.invalid',
      details: { signingAlgo },
    },
    { cause },
  );
}
