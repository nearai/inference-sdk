import { Buffer } from 'node:buffer';
import nacl from 'tweetnacl';
import { verifyOhttpKeyConfig } from '../src/core/ohttp-attestation';
import type { SigningIdentity } from '../src/types/attestation-common';
import type { OhttpAttestation } from '../src/types/ohttp';

const keyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7));
const keyConfig = Buffer.concat([
  Buffer.from('010020', 'hex'),
  Buffer.alloc(32, 0x33),
  Buffer.from('000400010001', 'hex'),
]);
const signer: SigningIdentity = {
  signingAlgo: 'ed25519',
  signingAddress: Buffer.from(keyPair.publicKey).toString('hex'),
};
const ohttpAttestation: OhttpAttestation = {
  signingAlgo: 'ed25519',
  signingKey: signer.signingAddress,
  keyConfig: keyConfig.toString('hex'),
  signature: Buffer.from(
    nacl.sign.detached(keyConfig, keyPair.secretKey),
  ).toString('hex'),
};

describe('OHTTP attestation key binding', () => {
  test('returns the signed raw configuration bytes with normalized hexadecimal inputs', () => {
    const result = verifyOhttpKeyConfig({
      signer: { ...signer, signingAddress: `0x${signer.signingAddress}` },
      ohttpAttestation: {
        ...ohttpAttestation,
        signingKey: ohttpAttestation.signingKey.toUpperCase(),
        keyConfig: `0X${ohttpAttestation.keyConfig.toUpperCase()}`,
        signature: `0x${ohttpAttestation.signature}`,
      },
    });

    expect(result).toEqual(new Uint8Array(keyConfig));
  });

  test.each<SigningIdentity>([
    { signingAlgo: 'ecdsa', signingAddress: '11'.repeat(20) },
    { signingAlgo: 'ed25519', signingAddress: '11'.repeat(32) },
  ])(
    'rejects a configuration signed by an unauthenticated key: $signingAlgo',
    (signer) => {
      expect(() => verifyOhttpKeyConfig({ ohttpAttestation, signer })).toThrow(
        expect.objectContaining({
          failure: { code: 'ohttp.signer_mismatch' },
        }),
      );
    },
  );

  test.each([
    { keyConfig: `02${ohttpAttestation.keyConfig.slice(2)}` },
    { signature: '00'.repeat(64) },
    { signature: '00'.repeat(63) },
    {
      signature: Buffer.from(
        nacl.sign.detached(
          Buffer.from(ohttpAttestation.keyConfig, 'utf8'),
          keyPair.secretKey,
        ),
      ).toString('hex'),
    },
  ])(
    'rejects modified evidence or a signature over the hex text: %p',
    (overrides) => {
      expect(() =>
        verifyOhttpKeyConfig({
          signer,
          ohttpAttestation: { ...ohttpAttestation, ...overrides },
        }),
      ).toThrow(
        expect.objectContaining({
          failure: { code: 'ohttp.signature_invalid' },
        }),
      );
    },
  );

  test.each(['signingKey', 'keyConfig', 'signature'] as const)(
    'reports malformed %s hexadecimal as an input error',
    (field) => {
      expect(() =>
        verifyOhttpKeyConfig({
          signer,
          ohttpAttestation: { ...ohttpAttestation, [field]: 'not-hex' },
        }),
      ).toThrow(
        expect.objectContaining({
          failure: {
            code: 'input.invalid',
            details: {
              field: `ohttpAttestation.${field}`,
              reason: 'invalid_hex',
            },
          },
        }),
      );
    },
  );
});
