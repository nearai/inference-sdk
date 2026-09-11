import { Buffer } from 'node:buffer';
import ed2curve from 'ed2curve';
import nacl from 'tweetnacl';
import { decryptE2eeText } from '../src/core/e2ee';

const serverCiphertext =
  '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7ca0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b743d22a6968fbbdf88cd066c79b3dacd53a6991f06ce8c564e03b7eb60e2376';

describe('Ed25519 v2 E2EE', () => {
  test('accepts the protocol representation of an empty encrypted field', () => {
    expect(
      decryptE2eeText({
        ciphertext: '',
        recipientSecretKey: new Uint8Array(32),
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
        recipientSecretKey,
        field: 'response.content',
      }),
    ).toBe('fixed v2 vector');
  });
});
