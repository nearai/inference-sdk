import { gcm } from '@noble/ciphers/aes';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { Buffer } from 'buffer';
import ed2curve from 'ed2curve';
import { ethers } from 'ethers';
import nacl from 'tweetnacl';
import type { SigningAlgo } from '../types/attestation-common';
import { hexToBuffer, utf8 } from '../utils/common';
import { VerificationError } from '../utils/errors';

const E2EE_KEY_BYTES = 32;
const ED25519_NONCE_BYTES = 24;
const ED25519_ENVELOPE_PREFIX_BYTES = E2EE_KEY_BYTES + ED25519_NONCE_BYTES;
const ECDSA_PUBLIC_KEY_BYTES = 65;
const ECDSA_RAW_PUBLIC_KEY_BYTES = 64;
const ECDSA_NONCE_BYTES = 12;
const ECDSA_ENVELOPE_PREFIX_BYTES = ECDSA_PUBLIC_KEY_BYTES + ECDSA_NONCE_BYTES;
const E2EE_AUTH_TAG_BYTES = 16;
const ED25519_HKDF_INFO = utf8('ed25519_encryption');
const ECDSA_HKDF_INFO = utf8('ecdsa_encryption');

/** A quote-bound model key selected for the E2EE protocol. */
export type E2eeModelKey = {
  readonly signingAlgo: SigningAlgo;
  readonly publicKey: string;
};

type Ed25519E2eeClientKeyPair = {
  readonly signingAlgo: 'ed25519';
  readonly publicKey: string;
  readonly x25519SecretKey: Uint8Array;
};

type EcdsaE2eeClientKeyPair = {
  readonly signingAlgo: 'ecdsa';
  /** A 64-byte uncompressed secp256k1 X || Y public key. */
  readonly publicKey: string;
  readonly privateKey: string;
};

export type E2eeClientKeyPair =
  | Ed25519E2eeClientKeyPair
  | EcdsaE2eeClientKeyPair;

type EncryptE2eeTextParams = {
  readonly plaintext: string;
  readonly modelKey: E2eeModelKey;
};

type DecryptE2eeTextParams = {
  readonly ciphertext: string;
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly field: string;
};

/** Create a fresh client key pair for the selected E2EE protocol. */
export function createE2eeClientKeyPair(
  signingAlgo: SigningAlgo = 'ed25519',
): E2eeClientKeyPair {
  if (signingAlgo === 'ecdsa') {
    const privateKey = `0x${Buffer.from(nacl.randomBytes(E2EE_KEY_BYTES)).toString('hex')}`;
    const signingKey = new ethers.SigningKey(privateKey);
    return {
      signingAlgo,
      publicKey: signingKey.publicKey.slice(4),
      privateKey,
    };
  }

  const keyPair = nacl.sign.keyPair();
  const x25519SecretKey = ed2curve.convertSecretKey(keyPair.secretKey);
  if (x25519SecretKey === null) {
    throw new VerificationError({ code: 'e2ee.model_public_key_invalid' });
  }
  return {
    signingAlgo,
    publicKey: Buffer.from(keyPair.publicKey).toString('hex'),
    x25519SecretKey,
  };
}

/** Encrypt one UTF-8 field for a quote-bound model E2EE key. */
export function encryptE2eeText({
  plaintext,
  modelKey,
}: EncryptE2eeTextParams): string {
  return modelKey.signingAlgo === 'ed25519'
    ? encryptEd25519Text({ plaintext, publicKey: modelKey.publicKey })
    : encryptEcdsaText({ plaintext, publicKey: modelKey.publicKey });
}

/** Decrypt one UTF-8 field produced by the selected E2EE protocol. */
export function decryptE2eeText({
  ciphertext,
  clientKeyPair,
  field,
}: DecryptE2eeTextParams): string {
  // The server represents an encrypted empty field as an empty string rather
  // than an envelope. Preserve that protocol value without treating it as a
  // malformed ciphertext.
  if (ciphertext === '') {
    return '';
  }
  try {
    return clientKeyPair.signingAlgo === 'ed25519'
      ? decryptEd25519Text({ ciphertext, clientKeyPair, field })
      : decryptEcdsaText({ ciphertext, clientKeyPair, field });
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

type EncryptProtocolTextParams = {
  readonly plaintext: string;
  readonly publicKey: string;
};

function encryptEd25519Text({
  plaintext,
  publicKey,
}: EncryptProtocolTextParams): string {
  const recipientX25519PublicKey = toX25519PublicKey(publicKey);
  const ephemeralSecretKey = nacl.randomBytes(E2EE_KEY_BYTES);
  const ephemeralPublicKey = nacl.scalarMult.base(ephemeralSecretKey);
  const nonce = nacl.randomBytes(ED25519_NONCE_BYTES);
  const encryptionKey = deriveE2eeKey({
    sharedSecret: nacl.scalarMult(ephemeralSecretKey, recipientX25519PublicKey),
    info: ED25519_HKDF_INFO,
  });
  const ciphertext = xchacha20poly1305(encryptionKey, nonce).encrypt(
    utf8(plaintext),
  );

  return Buffer.concat([
    Buffer.from(ephemeralPublicKey),
    Buffer.from(nonce),
    Buffer.from(ciphertext),
  ]).toString('hex');
}

function encryptEcdsaText({
  plaintext,
  publicKey,
}: EncryptProtocolTextParams): string {
  const recipientPublicKey = toEcdsaPublicKey(publicKey);
  const ephemeralPrivateKey = `0x${Buffer.from(nacl.randomBytes(E2EE_KEY_BYTES)).toString('hex')}`;
  const ephemeralKey = new ethers.SigningKey(ephemeralPrivateKey);
  const nonce = nacl.randomBytes(ECDSA_NONCE_BYTES);
  const encryptionKey = deriveE2eeKey({
    sharedSecret: ecdsaSharedSecret({
      privateKey: ephemeralPrivateKey,
      publicKey: recipientPublicKey,
    }),
    info: ECDSA_HKDF_INFO,
  });
  const ciphertext = gcm(encryptionKey, nonce).encrypt(utf8(plaintext));

  return Buffer.concat([
    Buffer.from(ephemeralKey.publicKey.slice(2), 'hex'),
    Buffer.from(nonce),
    Buffer.from(ciphertext),
  ]).toString('hex');
}

type DecryptProtocolTextParams<TClientKeyPair extends E2eeClientKeyPair> = {
  readonly ciphertext: string;
  readonly clientKeyPair: TClientKeyPair;
  readonly field: string;
};

function decryptEd25519Text({
  ciphertext,
  clientKeyPair,
  field,
}: DecryptProtocolTextParams<Ed25519E2eeClientKeyPair>): string {
  const envelope = hexToBuffer(ciphertext, field);
  if (envelope.length < ED25519_ENVELOPE_PREFIX_BYTES + E2EE_AUTH_TAG_BYTES) {
    throw new Error('E2EE envelope is too short');
  }
  const ephemeralPublicKey = envelope.subarray(0, E2EE_KEY_BYTES);
  const nonce = envelope.subarray(
    E2EE_KEY_BYTES,
    ED25519_ENVELOPE_PREFIX_BYTES,
  );
  const encrypted = envelope.subarray(ED25519_ENVELOPE_PREFIX_BYTES);
  const decryptionKey = deriveE2eeKey({
    sharedSecret: nacl.scalarMult(
      clientKeyPair.x25519SecretKey,
      ephemeralPublicKey,
    ),
    info: ED25519_HKDF_INFO,
  });
  const plaintext = xchacha20poly1305(decryptionKey, nonce).decrypt(encrypted);
  return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
}

function decryptEcdsaText({
  ciphertext,
  clientKeyPair,
  field,
}: DecryptProtocolTextParams<EcdsaE2eeClientKeyPair>): string {
  const envelope = hexToBuffer(ciphertext, field);
  if (envelope.length < ECDSA_ENVELOPE_PREFIX_BYTES + E2EE_AUTH_TAG_BYTES) {
    throw new Error('E2EE envelope is too short');
  }
  const ephemeralPublicKey = envelope.subarray(0, ECDSA_PUBLIC_KEY_BYTES);
  if (ephemeralPublicKey[0] !== 0x04) {
    throw new Error('ECDSA ephemeral public key is not uncompressed');
  }
  const nonce = envelope.subarray(
    ECDSA_PUBLIC_KEY_BYTES,
    ECDSA_ENVELOPE_PREFIX_BYTES,
  );
  const encrypted = envelope.subarray(ECDSA_ENVELOPE_PREFIX_BYTES);
  const decryptionKey = deriveE2eeKey({
    sharedSecret: ecdsaSharedSecret({
      privateKey: clientKeyPair.privateKey,
      publicKey: `0x${ephemeralPublicKey.toString('hex')}`,
    }),
    info: ECDSA_HKDF_INFO,
  });
  const plaintext = gcm(decryptionKey, nonce).decrypt(encrypted);
  return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
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

function toEcdsaPublicKey(publicKey: string): string {
  const bytes = hexToBuffer(publicKey, 'modelSigningPublicKey');
  if (bytes.length === ECDSA_RAW_PUBLIC_KEY_BYTES) {
    return `0x04${bytes.toString('hex')}`;
  }
  if (bytes.length === ECDSA_PUBLIC_KEY_BYTES && bytes[0] === 0x04) {
    return `0x${bytes.toString('hex')}`;
  }
  throw new VerificationError({ code: 'e2ee.model_public_key_invalid' });
}

type DeriveE2eeKeyParams = {
  readonly sharedSecret: Uint8Array;
  readonly info: Uint8Array;
};

function deriveE2eeKey({
  sharedSecret,
  info,
}: DeriveE2eeKeyParams): Uint8Array {
  return hkdf(sha256, sharedSecret, undefined, info, E2EE_KEY_BYTES);
}

type EcdsaSharedSecretParams = {
  readonly privateKey: string;
  readonly publicKey: string;
};

/** The legacy ECDSA protocol uses the X coordinate of the shared point. */
function ecdsaSharedSecret({
  privateKey,
  publicKey,
}: EcdsaSharedSecretParams): Uint8Array {
  const sharedPoint = ethers.getBytes(
    new ethers.SigningKey(privateKey).computeSharedSecret(publicKey),
  );
  return sharedPoint.subarray(1, E2EE_KEY_BYTES + 1);
}
