import { prepareE2eeChatRequest } from '../src';
import { NO_ALIASING_HEADER } from '../src/core/cloud-api';
import {
  createE2eeClientKeyPair,
  decryptE2eeText,
  encryptE2eeText,
} from '../src/core/e2ee';
import type { SigningAlgo } from '../src/types/attestation-common';

const endpoint = 'https://gateway.test/v1/chat/completions';
const prompt = {
  model: 'test-model',
  messages: [{ role: 'user', content: '私密问题' }],
};

function createModelKeys(signingAlgo: SigningAlgo = 'ed25519') {
  const keyPair = createE2eeClientKeyPair(signingAlgo);
  const modelKey = { signingAlgo, publicKey: keyPair.publicKey };
  return { modelKey, keyPair };
}

function chatRequest(init: RequestInit = {}): Request {
  return new Request(endpoint, {
    method: 'POST',
    body: JSON.stringify(prompt),
    ...init,
  });
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

describe.each(['ed25519', 'ecdsa'] as const)(
  '%s bare Chat E2EE',
  (signingAlgo) => {
    test('prepares protocol headers and a request that the model can decrypt', async () => {
      const { modelKey, keyPair } = createModelKeys(signingAlgo);
      const controller = new AbortController();
      const original = chatRequest({
        signal: controller.signal,
        headers: {
          authorization: 'Bearer caller-owned',
          'x-caller-header': 'preserved',
          'content-type': 'text/plain',
          'content-length': '1',
          'content-md5': 'original-body-md5',
          digest: 'sha-256=original-body-digest',
          'content-digest': 'sha-256=:original-body-digest:',
          'repr-digest': 'sha-256=:original-representation-digest:',
          'x-signing-algo': 'stale',
          'x-client-pub-key': 'stale',
          'x-model-pub-key': 'stale',
          'x-encryption-version': 'stale',
          'x-encrypt-all-fields': 'false',
          [NO_ALIASING_HEADER]: 'false',
        },
      });
      const prepared = await prepareE2eeChatRequest({
        request: original,
        modelKey,
      });
      const { headers } = prepared.request;
      expect(prepared.request.url).toBe(endpoint);
      expect(prepared.request.method).toBe('POST');
      expect(headers.get('authorization')).toBe('Bearer caller-owned');
      expect(headers.get('x-caller-header')).toBe('preserved');
      expect(headers.get('content-type')).toBe('application/json');
      expect(headers.get('content-length')).toBeNull();
      for (const name of [
        'content-md5',
        'digest',
        'content-digest',
        'repr-digest',
      ]) {
        expect(headers.has(name)).toBe(false);
      }
      expect(headers.get('x-signing-algo')).toBe(signingAlgo);
      expect(headers.get('x-model-pub-key')).toBe(keyPair.publicKey);
      expect(headers.get('x-client-pub-key')).toHaveLength(
        signingAlgo === 'ecdsa' ? 128 : 64,
      );
      expect(headers.get('x-encryption-version')).toBe(
        signingAlgo === 'ed25519' ? '2' : null,
      );
      expect(headers.get('x-encrypt-all-fields')).toBe('true');
      expect(headers.get(NO_ALIASING_HEADER)).toBe('true');

      const encrypted = await prepared.request.json();
      expect(encrypted.model).toBe(prompt.model);
      expect(encrypted.messages[0].role).toBe('user');
      expect(encrypted.messages[0].content).not.toBe(
        prompt.messages[0]?.content,
      );
      expect(
        decryptE2eeText({
          ciphertext: encrypted.messages[0].content,
          clientKeyPair: keyPair,
          field: 'messages[0].content',
        }),
      ).toBe(prompt.messages[0]?.content);
      expect(await original.json()).toEqual(prompt);
      expect(original.headers.get('content-length')).toBe('1');

      const reason = new Error('Cancel prepared request');
      controller.abort(reason);
      expect(prepared.request.signal.reason).toBe(reason);
    });

    test('decrypts JSON with the request key and rejects tampered ciphertext', async () => {
      const { modelKey } = createModelKeys(signingAlgo);
      const prepared = await prepareE2eeChatRequest({
        request: chatRequest(),
        modelKey,
      });
      const clientPublicKey = prepared.request.headers.get('x-client-pub-key');
      if (clientPublicKey === null) throw new Error('Expected client key');
      const ciphertext = encryptE2eeText({
        plaintext: '私密回答',
        modelKey: { signingAlgo, publicKey: clientPublicKey },
      });
      const body = {
        id: 'chatcmpl-bare',
        choices: [{ message: { role: 'assistant', content: ciphertext } }],
        usage: { total_tokens: 5 },
      };
      const response = await prepared.decryptResponse(
        jsonResponse(body, {
          status: 201,
          statusText: 'Created',
          headers: {
            'content-length': '99999',
            // Fetch has already decoded the HTTP content encoding.
            'content-encoding': 'gzip',
            'content-md5': 'encrypted-body-md5',
            digest: 'sha-256=encrypted-body-digest',
            'content-digest': 'sha-256=:encrypted-body-digest:',
            'repr-digest': 'sha-256=:encrypted-representation-digest:',
            etag: '"encrypted-body"',
            'last-modified': 'Thu, 17 Sep 2026 00:00:00 GMT',
            'x-response-header': 'preserved',
          },
        }),
      );
      expect(response.status).toBe(201);
      expect(response.statusText).toBe('Created');
      expect(response.headers.get('content-length')).toBeNull();
      for (const name of [
        'content-encoding',
        'content-md5',
        'digest',
        'content-digest',
        'repr-digest',
        'etag',
        'last-modified',
      ]) {
        expect(response.headers.has(name)).toBe(false);
      }
      expect(response.headers.get('content-type')).toBe('application/json');
      expect(response.headers.get('x-response-header')).toBe('preserved');
      expect(await response.json()).toEqual({
        ...body,
        choices: [{ message: { role: 'assistant', content: '私密回答' } }],
      });

      const tampered =
        ciphertext.slice(0, -1) + (ciphertext.endsWith('0') ? '1' : '0');
      await expect(
        prepared.decryptResponse(
          jsonResponse({
            ...body,
            choices: [{ message: { content: tampered } }],
          }),
        ),
      ).rejects.toMatchObject({ failure: { code: 'e2ee.decryption_failed' } });
    });

    test.each([
      { name: 'LF', lineEnding: '\n', separator: '\n\n' },
      { name: 'CRLF', lineEnding: '\r\n', separator: '\r\n\r\n' },
      { name: 'CR', lineEnding: '\r', separator: '\r\r' },
      { name: 'mixed', lineEnding: '\r', separator: '\n\n' },
    ])(
      'decrypts multiline SSE with $name endings split across individual bytes and preserves control records',
      async ({ lineEnding, separator }) => {
        const { modelKey } = createModelKeys(signingAlgo);
        const prepared = await prepareE2eeChatRequest({
          request: chatRequest({
            body: JSON.stringify({ ...prompt, stream: true }),
          }),
          modelKey,
        });
        const clientPublicKey =
          prepared.request.headers.get('x-client-pub-key');
        if (clientPublicKey === null) throw new Error('Expected client key');
        const chunk = {
          id: 'chatcmpl-stream',
          choices: [
            {
              delta: {
                content: encryptE2eeText({
                  plaintext: '流式回答',
                  modelKey: { signingAlgo, publicKey: clientPublicKey },
                }),
              },
            },
          ],
        };
        const prefix = `: 保活${separator}`;
        const controls = `event: message${lineEnding}id: part-1${lineEnding}`;
        const suffix =
          'event: error\ndata: {"message":"unchanged"}\n\ndata: [DONE]\n\n';
        const data = [
          `data: {"id":${JSON.stringify(chunk.id)},`,
          `data: "choices":${JSON.stringify(chunk.choices)}}`,
        ].join(lineEnding);
        const input = `${prefix}${controls}${data}${separator}${suffix}`;
        const source = new ReadableStream<Uint8Array>({
          start(controller) {
            for (const byte of new TextEncoder().encode(input)) {
              controller.enqueue(Uint8Array.of(byte));
            }
            controller.close();
          },
        });
        const response = await prepared.decryptResponse(
          new Response(source, {
            headers: {
              'content-type': 'text/event-stream; charset=utf-8',
              'content-length': '99999',
              'content-encoding': 'br',
              'content-digest': 'sha-256=:encrypted-stream-digest:',
            },
          }),
        );
        expect(response.headers.get('content-length')).toBeNull();
        expect(response.headers.has('content-encoding')).toBe(false);
        expect(response.headers.has('content-digest')).toBe(false);
        expect(response.headers.get('content-type')).toBe(
          'text/event-stream; charset=utf-8',
        );
        const decryptedChunk = {
          ...chunk,
          choices: [{ delta: { content: '流式回答' } }],
        };
        expect(await response.text()).toBe(
          `${prefix}${controls}data: ${JSON.stringify(decryptedChunk)}${separator}${suffix}`,
        );
      },
    );

    test('uses separate response keys for concurrent requests', async () => {
      const { modelKey } = createModelKeys(signingAlgo);
      const prepared = await Promise.all([
        prepareE2eeChatRequest({ request: chatRequest(), modelKey }),
        prepareE2eeChatRequest({ request: chatRequest(), modelKey }),
      ]);
      const firstKey = prepared[0].request.headers.get('x-client-pub-key');
      const secondKey = prepared[1].request.headers.get('x-client-pub-key');
      expect(firstKey).not.toBe(secondKey);
      if (firstKey === null) throw new Error('Expected first client key');
      const body = {
        choices: [
          {
            message: {
              content: encryptE2eeText({
                plaintext: 'Only for first request',
                modelKey: { signingAlgo, publicKey: firstKey },
              }),
            },
          },
        ],
      };
      await expect(
        prepared[0].decryptResponse(jsonResponse(body)),
      ).resolves.toBeInstanceOf(Response);
      await expect(
        prepared[1].decryptResponse(jsonResponse(body)),
      ).rejects.toMatchObject({
        failure: { code: 'e2ee.decryption_failed' },
      });
    });
  },
);

test('passes unsuccessful HTTP responses through without consuming them', async () => {
  const { modelKey } = createModelKeys();
  const prepared = await prepareE2eeChatRequest({
    request: chatRequest(),
    modelKey,
  });
  const response = new Response('Gateway unavailable', {
    status: 503,
    headers: { 'content-length': '19', 'content-type': 'text/plain' },
  });
  expect(await prepared.decryptResponse(response)).toBe(response);
  expect(response.bodyUsed).toBe(false);
  expect(response.headers.get('content-length')).toBe('19');
  expect(await response.text()).toBe('Gateway unavailable');
});

test.each([
  { body: '{invalid', reason: 'invalid_json' },
  { body: '{"messages":[]}', reason: 'unsupported_value' },
])('rejects invalid request body: $reason', async ({ body, reason }) => {
  const { modelKey } = createModelKeys();
  await expect(
    prepareE2eeChatRequest({ request: chatRequest({ body }), modelKey }),
  ).rejects.toMatchObject({
    failure: { code: 'api.invalid_input', details: { reason } },
  });
});

test('rejects an already aborted request with the original reason', async () => {
  const { modelKey } = createModelKeys();
  const reason = new Error('Cancelled before preparation');
  await expect(
    prepareE2eeChatRequest({
      request: chatRequest({ signal: AbortSignal.abort(reason) }),
      modelKey,
    }),
  ).rejects.toBe(reason);
});

test('does not wait for a stalled request body after cancellation', async () => {
  const { modelKey } = createModelKeys();
  const controller = new AbortController();
  const body = new TransformStream<Uint8Array>();
  const writer = body.writable.getWriter();
  const options = {
    method: 'POST',
    body: body.readable,
    duplex: 'half',
    signal: controller.signal,
  };
  const request = new Request(endpoint, options);
  const reason = new Error('Cancelled during upload');
  const preparation = prepareE2eeChatRequest({ request, modelKey });
  await writer.write(new TextEncoder().encode('{"model":'));
  controller.abort(reason);
  try {
    await expect(preparation).rejects.toBe(reason);
  } finally {
    await writer.close();
  }
});
