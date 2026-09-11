import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { Buffer } from 'buffer';
import ed2curve from 'ed2curve';
import nacl from 'tweetnacl';
import { hexToBuffer, utf8 } from '../utils/common';
import { VerificationError } from '../utils/errors';

const E2EE_KEY_BYTES = 32;
const E2EE_NONCE_BYTES = 24;
const E2EE_ENVELOPE_PREFIX_BYTES = E2EE_KEY_BYTES + E2EE_NONCE_BYTES;
const E2EE_AUTH_TAG_BYTES = 16;
const E2EE_HKDF_INFO = utf8('ed25519_encryption');

export type E2eeClientKeyPair = {
  readonly publicKey: string;
  readonly x25519SecretKey: Uint8Array;
};

type EncryptE2eeTextParams = {
  readonly plaintext: string;
  readonly recipientPublicKey: string;
};

type DecryptE2eeTextParams = {
  readonly ciphertext: string;
  readonly recipientSecretKey: Uint8Array;
  readonly field: string;
};

/** Create a fresh Ed25519 client identity and its X25519 decryption key. */
export function createE2eeClientKeyPair(): E2eeClientKeyPair {
  const keyPair = nacl.sign.keyPair();
  const x25519SecretKey = ed2curve.convertSecretKey(keyPair.secretKey);
  if (x25519SecretKey === null) {
    throw new VerificationError({ code: 'e2ee.model_public_key_invalid' });
  }
  return {
    publicKey: Buffer.from(keyPair.publicKey).toString('hex'),
    x25519SecretKey,
  };
}

/** Encrypt one UTF-8 field for an Ed25519 recipient under the v2 E2EE format. */
export function encryptE2eeText({
  plaintext,
  recipientPublicKey,
}: EncryptE2eeTextParams): string {
  const recipientX25519PublicKey = toX25519PublicKey(recipientPublicKey);
  const ephemeralSecretKey = nacl.randomBytes(E2EE_KEY_BYTES);
  const ephemeralPublicKey = nacl.scalarMult.base(ephemeralSecretKey);
  const nonce = nacl.randomBytes(E2EE_NONCE_BYTES);
  const encryptionKey = deriveE2eeKey(
    nacl.scalarMult(ephemeralSecretKey, recipientX25519PublicKey),
  );
  const ciphertext = xchacha20poly1305(encryptionKey, nonce).encrypt(
    utf8(plaintext),
  );

  return Buffer.concat([
    Buffer.from(ephemeralPublicKey),
    Buffer.from(nonce),
    Buffer.from(ciphertext),
  ]).toString('hex');
}

/** Decrypt one UTF-8 field produced by the v2 E2EE format. */
export function decryptE2eeText({
  ciphertext,
  recipientSecretKey,
  field,
}: DecryptE2eeTextParams): string {
  // The server represents an encrypted empty field as an empty string rather
  // than an envelope. Preserve that protocol value without treating it as a
  // malformed ciphertext.
  if (ciphertext === '') {
    return '';
  }
  try {
    const envelope = hexToBuffer(ciphertext, field);
    if (envelope.length < E2EE_ENVELOPE_PREFIX_BYTES + E2EE_AUTH_TAG_BYTES) {
      throw new Error('E2EE envelope is too short');
    }
    const ephemeralPublicKey = envelope.subarray(0, E2EE_KEY_BYTES);
    const nonce = envelope.subarray(E2EE_KEY_BYTES, E2EE_ENVELOPE_PREFIX_BYTES);
    const encrypted = envelope.subarray(E2EE_ENVELOPE_PREFIX_BYTES);
    const decryptionKey = deriveE2eeKey(
      nacl.scalarMult(recipientSecretKey, ephemeralPublicKey),
    );
    const plaintext = xchacha20poly1305(decryptionKey, nonce).decrypt(
      encrypted,
    );
    return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'e2ee.decryption_failed',
        details: { field },
      },
      { cause },
    );
  }
}

function toX25519PublicKey(publicKey: string): Uint8Array {
  const ed25519PublicKey = hexToBuffer(publicKey, 'modelSigningPublicKey');
  if (ed25519PublicKey.length !== E2EE_KEY_BYTES) {
    throw new VerificationError({ code: 'e2ee.model_public_key_invalid' });
  }
  const x25519PublicKey = ed2curve.convertPublicKey(ed25519PublicKey);
  if (x25519PublicKey === null) {
    throw new VerificationError({ code: 'e2ee.model_public_key_invalid' });
  }
  return x25519PublicKey;
}

function deriveE2eeKey(sharedSecret: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, undefined, E2EE_HKDF_INFO, E2EE_KEY_BYTES);
}
