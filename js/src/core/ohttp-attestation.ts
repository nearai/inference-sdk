import nacl from 'tweetnacl';
import type { VerifyOhttpKeyConfigParams } from '../types/ohttp';
import { hexToBuffer, requireByteLength } from '../utils/common';
import { VerificationError } from '../utils/errors';

/**
 * Authenticate the advertised OHTTP configuration against a verified signer.
 * The caller must first verify the Gateway or direct model attestation that
 * supplied this signer. The returned bytes still need protocol parsing before use.
 */
export function verifyOhttpKeyConfig({
  ohttpAttestation,
  signer,
}: VerifyOhttpKeyConfigParams): Uint8Array {
  if (signer.signingAlgo !== 'ed25519') {
    throw new VerificationError({ code: 'ohttp.signer_mismatch' });
  }
  const signingKey = requireByteLength({
    value: ohttpAttestation.signingKey,
    byteLength: nacl.sign.publicKeyLength,
    label: 'ohttpAttestation.signingKey',
  });
  const authenticatedKey = requireByteLength({
    value: signer.signingAddress,
    byteLength: nacl.sign.publicKeyLength,
    label: 'signer.signingAddress',
  });
  if (!signingKey.equals(authenticatedKey)) {
    throw new VerificationError({ code: 'ohttp.signer_mismatch' });
  }
  const keyConfig = hexToBuffer(
    ohttpAttestation.keyConfig,
    'ohttpAttestation.keyConfig',
  );
  const signature = hexToBuffer(
    ohttpAttestation.signature,
    'ohttpAttestation.signature',
  );
  if (
    signature.length !== nacl.sign.signatureLength ||
    !nacl.sign.detached.verify(keyConfig, signature, signingKey)
  ) {
    throw new VerificationError({ code: 'ohttp.signature_invalid' });
  }
  return new Uint8Array(keyConfig);
}
