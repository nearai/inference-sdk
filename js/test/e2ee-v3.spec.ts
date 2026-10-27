import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import ed2curve from 'ed2curve';
import nacl from 'tweetnacl';
import {
  buildE2eeFieldAad,
  buildE2eeRequestAad,
  decryptE2eeText,
  type E2eeClientKeyPair,
  encryptE2eeText,
} from '../src/core/e2ee';
import {
  createE2eeChatSseTransform,
  decryptE2eeChatResponse,
  decryptE2eeChatStreamChunk,
  parseE2eeChatResponse,
} from '../src/core/e2ee-chat';
import { VerificationError } from '../src/utils/errors';

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
  const associatedData = buildE2eeFieldAad(
    buildE2eeRequestAad({
      signingAlgo: vector.signing_algo,
      publicKey: vector.reply_public,
    }),
    'messages[].content',
  );
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
        buildE2eeFieldAad(
          buildE2eeRequestAad({
            signingAlgo: 'ecdsa',
            publicKey: vector.reply_public.slice(2),
          }),
          'messages[].content',
        ),
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
  test('rejects a different recipient, field, suite byte, or empty AAD', () => {
    const changedKey = buildE2eeFieldAad(
      buildE2eeRequestAad({
        signingAlgo: vector.signing_algo,
        publicKey: vector.model_public,
      }),
      'messages[].content',
    );
    const changedSuite = Uint8Array.from(associatedData);
    changedSuite[22] = 0xff;
    const changedField = buildE2eeFieldAad(
      buildE2eeRequestAad({
        signingAlgo: vector.signing_algo,
        publicKey: vector.reply_public,
      }),
      'tool_choice.function.name',
    );
    for (const aad of [
      changedKey,
      changedField,
      changedSuite,
      new Uint8Array(),
    ]) {
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
  test.each([false, true])(
    'validates rich content parts (streaming=%s)',
    (streaming) => {
      const field = streaming ? 'delta' : 'message';
      const ciphertext = encryptE2eeText({
        plaintext: 'answer',
        modelKey: {
          signingAlgo: vector.signing_algo,
          publicKey: vector.model_public,
        },
      });
      const part = { type: 'text', text: ciphertext };
      const decrypt = (content: unknown[]) => {
        const body = { id: 'chat-v3', choices: [{ [field]: { content } }] };
        return streaming
          ? decryptE2eeChatStreamChunk({ chunk: body, clientKeyPair })
          : decryptE2eeChatResponse({ body, clientKeyPair });
      };
      expect(decrypt([part])).toEqual({
        id: 'chat-v3',
        choices: [{ [field]: { content: [{ type: 'text', text: 'answer' }] } }],
      });
      expect(decrypt([])).toEqual({
        id: 'chat-v3',
        choices: [{ [field]: { content: [] } }],
      });
      for (const invalid of ['plaintext', 0, true, null, ['nested']]) {
        expect(() => decrypt([part, invalid])).toThrow(VerificationError);
      }
    },
  );
  test('rejects malformed protected containers in JSON and SSE', async () => {
    const choices: Record<string, unknown>[] = [
      { message: { tool_calls: { function: { arguments: 'plaintext' } } } },
      { message: { tool_calls: [null] } },
      { message: { tool_calls: [{ function: ['plaintext'] }] } },
      { message: { audio: [{ data: 'plaintext' }] } },
      { message: { function_call: ['plaintext'] } },
      { logprobs: [] },
      { logprobs: { content: { token: 'plaintext' } } },
      { logprobs: { content: [null] } },
      { logprobs: { content: [{ top_logprobs: { token: 'plaintext' } }] } },
    ];
    for (const choice of choices) {
      const body = { id: 'chat-containers', choices: [choice] };
      expect(() =>
        decryptE2eeChatResponse({
          body: parseE2eeChatResponse({ body }),
          clientKeyPair,
        }),
      ).toThrow(VerificationError);
      const chunk = {
        id: 'chat-containers',
        choices: [
          choice.message === undefined ? choice : { delta: choice.message },
        ],
      };
      const source = new Response(`data: ${JSON.stringify(chunk)}\n\n`).body;
      if (source === null) throw new Error('missing fixture body');
      const response = new Response(
        source.pipeThrough(createE2eeChatSseTransform({ clientKeyPair })),
      );
      await expect(response.text()).rejects.toThrow(VerificationError);
    }
    const valid = {
      id: 'chat-fragment',
      choices: [
        {
          delta: { tool_calls: [{ index: 0, id: 'call-1' }], audio: null },
          logprobs: null,
        },
      ],
    };
    expect(decryptE2eeChatStreamChunk({ chunk: valid, clientKeyPair })).toEqual(
      valid,
    );
  });
});
