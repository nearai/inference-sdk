import { Buffer } from 'node:buffer';
import { createDecipheriv, createECDH, hkdfSync } from 'node:crypto';
import ed2curve from 'ed2curve';
import nacl from 'tweetnacl';
import {
  createE2eeClientKeyPair,
  decryptE2eeText,
  encryptE2eeText,
} from '../src/core/e2ee';
import { createE2eeChatSseTransform } from '../src/core/e2ee-chat';

const serverCiphertext =
  '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7ca0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b743d22a6968fbbdf88cd066c79b3dacd53a6991f06ce8c564e03b7eb60e2376';

describe('Ed25519 v2 E2EE', () => {
  test('accepts the protocol representation of an empty encrypted field', () => {
    expect(
      decryptE2eeText({
        ciphertext: '',
        clientKeyPair: {
          signingAlgo: 'ed25519',
          publicKey: '',
          x25519SecretKey: new Uint8Array(32),
        },
        field: 'response.content',
      }),
    ).toBe('');
  });

  test('decrypts a fixed protocol-v2 response vector', () => {
    const signingKeyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 0x0b));
    const recipientSecretKey = ed2curve.convertSecretKey(
      signingKeyPair.secretKey,
    );
    if (recipientSecretKey === null) {
      throw new Error('Failed to derive the test X25519 key');
    }

    expect(
      decryptE2eeText({
        ciphertext: serverCiphertext,
        clientKeyPair: {
          signingAlgo: 'ed25519',
          publicKey: keyHex(signingKeyPair.publicKey),
          x25519SecretKey: recipientSecretKey,
        },
        field: 'response.content',
      }),
    ).toBe('fixed v2 vector');
  });

  test('preserves empty SSE data records', async () => {
    const input = 'data:\n\ndata\n\n';
    const source = new Response(input).body;
    if (source === null) {
      throw new Error('Expected an SSE response body');
    }

    const transformed = new Response(
      source.pipeThrough(
        createE2eeChatSseTransform({
          clientKeyPair: createE2eeClientKeyPair(),
        }),
      ),
    );

    await expect(transformed.text()).resolves.toBe(input);
  });
});

const ecdsaModelPublicKey =
  '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
const ecdsaServerCiphertext =
  '04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a000102030405060708090a0bb70c17944e668fbe04a547595e40927c708a34b9e7c4cb5b9917a6fb2240653b2a142b86';

describe('ECDSA E2EE', () => {
  test('decrypts a fixed legacy ECDSA response vector', () => {
    expect(
      decryptE2eeText({
        ciphertext: ecdsaServerCiphertext,
        clientKeyPair: {
          signingAlgo: 'ecdsa',
          publicKey: ecdsaModelPublicKey,
          privateKey: `0x${'00'.repeat(31)}01`,
        },
        field: 'response.content',
      }),
    ).toBe('near-ai ecdsa vector');
  });

  test('uses a canonical raw public key and decrypts a round trip', () => {
    const recipient = createE2eeClientKeyPair('ecdsa');
    if (recipient.signingAlgo !== 'ecdsa') {
      throw new Error('Expected an ECDSA client key pair');
    }

    const ciphertext = encryptE2eeText({
      plaintext: 'private ECDSA request',
      modelKey: { signingAlgo: 'ecdsa', publicKey: recipient.publicKey },
    });

    expect(recipient.publicKey).toHaveLength(128);
    expect(ciphertext.slice(0, 2)).toBe('04');
    expect(
      decryptE2eeText({
        ciphertext,
        clientKeyPair: recipient,
        field: 'request.content',
      }),
    ).toBe('private ECDSA request');
  });

  test('produces a legacy ECDSA envelope accepted by Node crypto', () => {
    const model = createECDH('secp256k1');
    model.generateKeys();
    const modelPublicKey = model.getPublicKey('hex', 'uncompressed').slice(2);
    const ciphertext = encryptE2eeText({
      plaintext: 'independent ECDSA check',
      modelKey: { signingAlgo: 'ecdsa', publicKey: modelPublicKey },
    });
    const envelope = Buffer.from(ciphertext, 'hex');
    const ephemeralPublicKey = envelope.subarray(0, 65);
    const nonce = envelope.subarray(65, 77);
    const encrypted = envelope.subarray(77, -16);
    const tag = envelope.subarray(-16);
    const encryptionKey = Buffer.from(
      hkdfSync(
        'sha256',
        model.computeSecret(ephemeralPublicKey),
        Buffer.alloc(0),
        'ecdsa_encryption',
        32,
      ),
    );
    const decipher = createDecipheriv('aes-256-gcm', encryptionKey, nonce);
    decipher.setAuthTag(tag);

    expect(
      Buffer.concat([decipher.update(encrypted), decipher.final()]).toString(
        'utf8',
      ),
    ).toBe('independent ECDSA check');
  });
});

function keyHex(value: Uint8Array): string {
  return Buffer.from(value).toString('hex');
}
