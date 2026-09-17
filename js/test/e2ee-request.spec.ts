import { Buffer } from 'node:buffer';
import { computeAddress } from 'ethers';
import { prepareE2eeChatRequest } from '../src';
import { verifyModelAttestation } from '../src/core/attestation-model';
import { NO_ALIASING_HEADER } from '../src/core/cloud-api';
import {
  createE2eeClientKeyPair,
  decryptE2eeText,
  encryptE2eeText,
} from '../src/core/e2ee';
import type { SigningAlgo } from '../src/types/attestation-common';
import { createModelAttestation, createModelQuote, nonce } from './fixtures';

const endpoint = 'https://gateway.test/v1/chat/completions';
const prompt = {
  model: 'test-model',
  messages: [{ role: 'user', content: '私密问题' }],
};

async function createVerifiedModel(signingAlgo: SigningAlgo = 'ed25519') {
  const keyPair = createE2eeClientKeyPair(signingAlgo);
  const signingAddress =
    signingAlgo === 'ecdsa'
      ? computeAddress(`0x04${keyPair.publicKey}`)
      : keyPair.publicKey;
  const signerBinding = Buffer.alloc(32);
  Buffer.from(signingAddress.replace(/^0x/, ''), 'hex').copy(signerBinding);
  const quote = createModelQuote({
    reportData: Buffer.concat([signerBinding, Buffer.from(nonce, 'hex')]),
  });
  const attestation = await verifyModelAttestation({
    attestation: createModelAttestation({
      signer: { signingAlgo, signingAddress },
      signingPublicKey: keyPair.publicKey,
    }),
    clientBinding: { nonce },
    verifiers: { quote: () => quote },
  });
  return { attestation, keyPair };
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
      const { attestation, keyPair } = await createVerifiedModel(signingAlgo);
      const controller = new AbortController();
      const original = chatRequest({
        signal: controller.signal,
        headers: {
          authorization: 'Bearer caller-owned',
          'x-caller-header': 'preserved',
          'content-type': 'text/plain',
          'content-length': '1',
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
        attestation,
      });
      const { headers } = prepared.request;
      expect(prepared.request.url).toBe(endpoint);
      expect(prepared.request.method).toBe('POST');
      expect(headers.get('authorization')).toBe('Bearer caller-owned');
      expect(headers.get('x-caller-header')).toBe('preserved');
      expect(headers.get('content-type')).toBe('application/json');
      expect(headers.get('content-length')).toBeNull();
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
      const { attestation } = await createVerifiedModel(signingAlgo);
      const prepared = await prepareE2eeChatRequest({
        request: chatRequest(),
        attestation,
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
            'x-response-header': 'preserved',
          },
        }),
      );
      expect(response.status).toBe(201);
      expect(response.statusText).toBe('Created');
      expect(response.headers.get('content-length')).toBeNull();
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

    test('decrypts SSE split across individual bytes and preserves control records', async () => {
      const { attestation } = await createVerifiedModel(signingAlgo);
      const prepared = await prepareE2eeChatRequest({
        request: chatRequest({
          body: JSON.stringify({ ...prompt, stream: true }),
        }),
        attestation,
      });
      const clientPublicKey = prepared.request.headers.get('x-client-pub-key');
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
      const prefix = ': 保活\r\n\r\n';
      const suffix =
        'event: error\ndata: {"message":"unchanged"}\n\ndata: [DONE]\n\n';
      const input = `${prefix}data: ${JSON.stringify(chunk)}\r\n\r\n${suffix}`;
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
          },
        }),
      );
      expect(response.headers.get('content-length')).toBeNull();
      expect(response.headers.get('content-type')).toBe(
        'text/event-stream; charset=utf-8',
      );
      const decryptedChunk = {
        ...chunk,
        choices: [{ delta: { content: '流式回答' } }],
      };
      expect(await response.text()).toBe(
        `${prefix}data: ${JSON.stringify(decryptedChunk)}\r\n\r\n${suffix}`,
      );
    });

    test('uses separate response keys for concurrent requests', async () => {
      const { attestation } = await createVerifiedModel(signingAlgo);
      const prepared = await Promise.all([
        prepareE2eeChatRequest({ request: chatRequest(), attestation }),
        prepareE2eeChatRequest({ request: chatRequest(), attestation }),
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
  const { attestation } = await createVerifiedModel();
  const prepared = await prepareE2eeChatRequest({
    request: chatRequest(),
    attestation,
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

test('rejects verified evidence without an encryption public key', async () => {
  const { attestation } = await createVerifiedModel();
  await expect(
    prepareE2eeChatRequest({
      request: chatRequest(),
      attestation: { ...attestation, signingPublicKey: undefined },
    }),
  ).rejects.toMatchObject({
    failure: { code: 'e2ee.model_public_key_required' },
  });
});

test.each([
  { body: '{invalid', reason: 'invalid_json' },
  { body: '{"messages":[]}', reason: 'unsupported_value' },
])('rejects invalid request body: $reason', async ({ body, reason }) => {
  const { attestation } = await createVerifiedModel();
  await expect(
    prepareE2eeChatRequest({ request: chatRequest({ body }), attestation }),
  ).rejects.toMatchObject({
    failure: { code: 'api.invalid_input', details: { reason } },
  });
});

test('rejects an already aborted request with the original reason', async () => {
  const { attestation } = await createVerifiedModel();
  const reason = new Error('Cancelled before preparation');
  await expect(
    prepareE2eeChatRequest({
      request: chatRequest({ signal: AbortSignal.abort(reason) }),
      attestation,
    }),
  ).rejects.toBe(reason);
});

test('does not wait for a stalled request body after cancellation', async () => {
  const { attestation } = await createVerifiedModel();
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
  const preparation = prepareE2eeChatRequest({ request, attestation });
  await writer.write(new TextEncoder().encode('{"model":'));
  controller.abort(reason);
  try {
    await expect(preparation).rejects.toBe(reason);
  } finally {
    await writer.close();
  }
});
