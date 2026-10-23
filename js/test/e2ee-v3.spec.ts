import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import ed2curve from 'ed2curve';
import nacl from 'tweetnacl';
import {
  buildE2eeRequestAad,
  decryptE2eeText,
  type E2eeClientKeyPair,
  encryptE2eeText,
} from '../src/core/e2ee';
import { decryptE2eeChatResponse } from '../src/core/e2ee-chat';

type Vector = {
  signing_algo: 'ecdsa' | 'ed25519';
  model_secret: string;
  model_public: string;
  reply_public: string;
  aad: string;
  plaintext: string;
  ciphertext: string;
};
const { vectors } = JSON.parse(
  readFileSync(resolve(__dirname, '../../test-fixtures/e2ee-v3.json'), 'utf8'),
) as { vectors: Vector[] };

describe.each(vectors)('v3 $signing_algo shared vectors', (vector) => {
  const seed = Buffer.from(vector.model_secret, 'hex');
  const clientKeyPair: E2eeClientKeyPair =
    vector.signing_algo === 'ecdsa'
      ? {
          signingAlgo: 'ecdsa',
          publicKey: vector.model_public,
          privateKey: `0x${vector.model_secret}`,
        }
      : {
          signingAlgo: 'ed25519',
          publicKey: vector.model_public,
          x25519SecretKey: ed2curve.convertSecretKey(
            nacl.sign.keyPair.fromSeed(seed).secretKey,
          ),
        };
  const associatedData = buildE2eeRequestAad({
    signingAlgo: vector.signing_algo,
    publicKey: vector.reply_public,
  });
  test('matches the canonical AAD and decrypts the independent request vector', () => {
    expect(Buffer.from(associatedData).toString('hex')).toBe(vector.aad);
    expect(
      decryptE2eeText({
        ciphertext: vector.ciphertext,
        clientKeyPair,
        field: 'request',
        associatedData,
      }),
    ).toBe(vector.plaintext);
    if (vector.signing_algo === 'ecdsa') {
      expect(
        buildE2eeRequestAad({
          signingAlgo: 'ecdsa',
          publicKey: vector.reply_public.slice(2),
        }),
      ).toEqual(associatedData);
    }
    const ciphertext = encryptE2eeText({
      plaintext: vector.plaintext,
      modelKey: {
        signingAlgo: vector.signing_algo,
        publicKey: vector.model_public,
        associatedData,
      },
    });
    expect(
      decryptE2eeText({
        ciphertext,
        clientKeyPair,
        field: 'request',
        associatedData,
      }),
    ).toBe(vector.plaintext);
  });
  test('rejects a different recipient, suite byte, or empty AAD', () => {
    const changedKey = buildE2eeRequestAad({
      signingAlgo: vector.signing_algo,
      publicKey: vector.model_public,
    });
    const changedSuite = Uint8Array.from(associatedData);
    changedSuite[22] = 0xff;
    for (const aad of [changedKey, changedSuite, new Uint8Array()]) {
      expect(() =>
        decryptE2eeText({
          ciphertext: vector.ciphertext,
          clientKeyPair,
          field: 'request',
          associatedData: aad,
        }),
      ).toThrow();
    }
  });
  test('rejects clear logprob bytes and tool arguments', () => {
    for (const choice of [
      { message: {}, logprobs: { content: [{ bytes: [115] }] } },
      { message: { tool_calls: [{ function: { arguments: '{}' } }] } },
      {
        message: {
          tool_calls: [{ function: { arguments: { secret: true } } }],
        },
      },
    ]) {
      expect(() =>
        decryptE2eeChatResponse({
          body: { id: 'chat-v3', choices: [choice] },
          clientKeyPair,
        }),
      ).toThrow();
    }
  });
});
