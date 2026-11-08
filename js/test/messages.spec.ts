import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import Anthropic from '@anthropic-ai/sdk';
import {
  ApiError,
  DirectInferenceClient,
  getSdkError,
  InferenceClient,
} from '../src';
import { createEcdsaGateway } from './ecdsa-gateway-fixtures';
import { tlsFingerprint } from './fixtures';
import {
  baseUrl,
  chatRequest,
  createTestGateway,
  inferenceClientOptions,
  jsonResponse,
  keyPair,
  mockNodeGatewayAttestation,
  model,
  TestNodeInferenceClient,
} from './inference-client-fixtures';
import { createOhttpEndpoint } from './ohttp-fixtures';

describe('Messages API', () => {
  afterEach(() => jest.restoreAllMocks());

  function messagesGateway({
    streaming = false,
    tamper = false,
    providerReceipt = false,
    missingId = false,
    status = 200,
    retrySignature = false,
    tee = false,
    rawBody = undefined as Uint8Array | undefined,
  } = {}) {
    const gateway = createTestGateway({
      providerType: tee ? 'vllm' : 'openai',
      attestationSupported: tee,
    });
    const requests: Request[] = [];
    let signatureCalls = 0;
    let receipt: Record<string, string>;
    const raw = Buffer.from(
      rawBody ??
        readFileSync(
          resolve(
            __dirname,
            './fixtures/messages',
            streaming ? 'message.sse' : 'message.json',
          ),
        ),
    );
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === '/v1/messages') {
        gateway.expectRequestHeader(request);
        expect(gateway.state.gatewayAttestationRequests).toBeGreaterThan(0);
        expect(request.headers.get('x-no-aliasing')).toBe('true');
        expect(request.headers.has('x-client-pub-key')).toBe(false);
        expect(request.headers.has('x-model-pub-key')).toBe(false);
        expect(request.headers.has('x-api-key')).toBe(false);
        expect(request.headers.get('anthropic-version')).toBeTruthy();
        requests.push(request.clone());
        const body = new Uint8Array(await request.arrayBuffer());
        receipt = providerReceipt
          ? gateway.createProviderSignature(body, raw)
          : gateway.createGatewaySignature(body, raw);
        const visible = missingId
          ? Buffer.from(
              streaming
                ? 'event: response.output_item.added\ndata: {"id":"item-only","item":{"id":"msg_1"}}\n\n'
                : '{"output":[]}',
            )
          : tamper
            ? Buffer.from(raw.toString().replace('Hello', 'Altered'))
            : raw;
        return new Response(
          new ReadableStream({
            start(controller) {
              for (let i = 0; i < visible.length; i += 7)
                controller.enqueue(visible.subarray(i, i + 7));
              controller.close();
            },
          }),
          {
            status,
            headers: {
              'content-type': streaming
                ? 'text/event-stream'
                : 'application/json',
            },
          },
        );
      }
      if (url.pathname === '/v1/signature/msg_fixture') {
        signatureCalls++;
        if (retrySignature && signatureCalls === 1)
          return new Response('', { status: 503 });
        return jsonResponse(receipt);
      }
      return gateway.fetch(request);
    };
    return {
      gateway,
      fetch,
      requests,
      raw,
      signatureCalls: () => signatureCalls,
    };
  }

  test('classifies SDK failures wrapped by the native Messages client without I/O', async () => {
    const fixture = messagesGateway();
    const network = jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: true,
    });
    let caught: unknown;
    try {
      await client.messages.create({ model, messages: [], max_tokens: 1 });
    } catch (error) {
      caught = error;
    }
    expect(getSdkError(caught)?.failure.code).toBe('api.invalid_input');
    expect(network).not.toHaveBeenCalled();
  });

  test.each([false, true])(
    'preserves the original receipt after a duplicate ID (stream: %s)',
    async (streaming) => {
      const fixture = messagesGateway({ streaming });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      const consume = async () => {
        const response = await client.fetch(
          `${baseUrl}messages`,
          chatRequest({ stream: streaming }),
        );
        return response.text();
      };
      await consume();
      const verified = await client.verifyResponse('msg_fixture');
      await expect(consume()).rejects.toMatchObject({
        failure: { code: 'api.duplicate_completion_id' },
      });
      expect(await client.verifyResponse('msg_fixture')).toBe(verified);
      expect(fixture.signatureCalls()).toBe(1);
      expect(fixture.requests).toHaveLength(2);
    },
  );

  test.each([false, true])(
    'disables receipt retention with zero TTL (stream: %s)',
    async (streaming) => {
      const fixture = messagesGateway({ streaming });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
        responseCacheTimeToLiveMs: 0,
      });
      for (let index = 0; index < 2; index += 1) {
        const response = await client.fetch(
          `${baseUrl}messages`,
          chatRequest({ stream: streaming }),
        );
        await response.text();
        await expect(
          client.verifyResponse('msg_fixture'),
        ).rejects.toMatchObject({
          failure: { code: 'api.completion_not_found' },
        });
      }
      expect(fixture.signatureCalls()).toBe(0);
    },
  );

  test.each([false, true])(
    'expires receipts before delayed cleanup and allows ID reuse (stream: %s)',
    async (streaming) => {
      const fixture = messagesGateway({ streaming });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const now = jest.spyOn(Date, 'now').mockReturnValue(1000);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
        responseCacheTimeToLiveMs: 100,
      });
      const consume = async () => {
        const response = await client.fetch(
          `${baseUrl}messages`,
          chatRequest({ stream: streaming }),
        );
        await response.text();
      };
      await consume();
      await client.verifyResponse('msg_fixture');
      now.mockReturnValue(1100);
      await expect(client.verifyResponse('msg_fixture')).rejects.toMatchObject({
        failure: { code: 'api.completion_not_found' },
      });
      await consume();
      await client.verifyResponse('msg_fixture');
      expect(fixture.signatureCalls()).toBe(2);
    },
  );

  const messageStart =
    'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_fixture"}}\n\n';
  test.each([
    {
      name: 'message stop',
      ending: 'event: message_stop\ndata: {"type":"message_stop"}\n\n',
      valid: true,
    },
    {
      name: 'data-only stop',
      ending: 'data: {"type":"message_stop"}\n\n',
      valid: true,
    },
    { name: 'missing message stop', ending: '', valid: false },
    {
      name: 'second message ID',
      ending:
        'event: message_start\ndata: {"type":"message_start","message":{"id":"other"}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n',
      valid: false,
    },
    {
      name: 'stream error',
      ending:
        'event: error\ndata: {"type":"error","error":{"type":"overloaded_error","message":"overloaded"}}\n\n',
      valid: false,
    },
  ])('Messages stream receipt: $name', async ({ ending, valid }) => {
    const fixture = messagesGateway({
      streaming: true,
      rawBody: Buffer.from(messageStart + ending),
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    let body: string | undefined;
    try {
      const response = await client.fetch(
        `${baseUrl}messages`,
        chatRequest({ stream: true }),
      );
      body = Buffer.from(await response.arrayBuffer()).toString('utf8');
    } catch (error) {
      if (valid) throw error;
      expect(error).toBeInstanceOf(ApiError);
    }
    if (valid) {
      expect(body).toBe(messageStart + ending);
      await expect(client.verifyResponse('msg_fixture')).resolves.toMatchObject(
        { signatureKind: 'gateway' },
      );
    } else {
      await expect(client.verifyResponse('msg_fixture')).rejects.toBeInstanceOf(
        ApiError,
      );
      expect(fixture.signatureCalls()).toBe(0);
    }
    expect(fixture.requests).toHaveLength(1);
  });

  test.each(
    [false, true].flatMap((streaming) =>
      [false, true].flatMap((ohttp) =>
        [false, true].map((external) => ({
          streaming,
          ohttp,
          external,
          tee: false,
        })),
      ),
    ),
  )('creates and verifies exact bytes: %j', async (scenario) => {
    const fixture = messagesGateway(scenario);
    const endpoint = scenario.ohttp
      ? await createOhttpEndpoint({
          fetch: fixture.fetch,
          signingKey: keyPair(1),
        })
      : undefined;
    jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(endpoint?.fetch ?? fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
      ohttp: scenario.ohttp,
      signingAlgo: 'ed25519',
    });
    const api = scenario.external
      ? new Anthropic({
          apiKey: 'external',
          maxRetries: 0,
          baseURL: new URL('..', baseUrl).toString(),
          fetch: client.fetch,
        }).messages
      : client.messages;
    const messages: Anthropic.MessageParam[] = [
      {
        role: 'assistant',
        content: [
          { type: 'tool_use', id: 'prior', name: 'weather', input: {} },
        ],
      },
      {
        role: 'user',
        content: [
          {
            type: 'tool_result',
            tool_use_id: 'prior',
            content: '{"temperature":20}',
          },
        ],
      },
    ];
    if (scenario.streaming) {
      const events = [];
      const stream = await api.create({
        model,
        messages,
        max_tokens: 128,
        stream: true,
      });
      for await (const event of stream) events.push(event);
      expect(events.map((event) => event.type)).toContain(
        'content_block_delta',
      );
      expect(events.at(-1)).toMatchObject({
        type: 'message_stop',
      });
    } else {
      const response = await api.create({ model, messages, max_tokens: 128 });
      expect(response.id).toBe('msg_fixture');
      expect(response.content[1]).toMatchObject({
        type: 'tool_use',
        input: { city: 'Beijing' },
      });
    }
    expect(await fixture.requests[0].json()).toMatchObject({
      messages,
      max_tokens: 128,
    });
    await expect(client.verifyResponse('msg_fixture')).resolves.toMatchObject({
      id: 'msg_fixture',
      signatureKind: 'gateway',
    });
    await expect(client.verifyResponse('toolu_fixture')).rejects.toMatchObject({
      failure: { code: 'api.completion_not_found' },
    });
    expect(fixture.requests).toHaveLength(1);
    if (endpoint)
      expect(
        endpoint.requests.some(
          (request) => new URL(request.url).pathname === '/ohttp',
        ),
      ).toBe(true);
  });

  test('preserves Node TLS pinning for Messages', async () => {
    const fixture = messagesGateway();
    mockNodeGatewayAttestation({ gateway: fixture.gateway });
    const client = new TestNodeInferenceClient(
      { ...inferenceClientOptions(fixture.gateway), e2ee: false },
      fixture.fetch,
    );
    const response = await client.messages.create({
      model,
      messages: [{ role: 'user', content: 'Hello' }],
      max_tokens: 128,
    });
    await expect(client.verifyResponse(response.id)).resolves.toMatchObject({
      signatureKind: 'gateway',
    });
    expect(client.pinnedSpkiFingerprints).toEqual([tlsFingerprint]);
  });

  test.each([false, true])(
    'rejects tampered bytes (stream: %s)',
    async (streaming) => {
      const fixture = messagesGateway({ streaming, tamper: true });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      const response = await client.fetch(
        `${baseUrl}messages`,
        chatRequest({ input: 'Hello', stream: streaming }),
      );
      await response.text();
      await expect(client.verifyResponse('msg_fixture')).rejects.toMatchObject({
        failure: { code: 'signature.payload_mismatch' },
      });
    },
  );

  test('requires a Gateway receipt even when model evidence was verified', async () => {
    const fixture = messagesGateway({ providerReceipt: true, tee: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    await client.messages.create({
      model,
      messages: [{ role: 'user', content: 'Hello' }],
      max_tokens: 128,
    });
    await expect(client.verifyResponse('msg_fixture')).rejects.toMatchObject({
      failure: { code: 'signature.kind_mismatch' },
    });
  });

  test('retries signature lookup without repeating inference', async () => {
    const fixture = messagesGateway({ retrySignature: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    await client.messages.create({
      model,
      messages: [{ role: 'user', content: 'Hello' }],
      max_tokens: 128,
    });
    await expect(client.verifyResponse('msg_fixture')).rejects.toMatchObject({
      failure: { code: 'api.http_status' },
    });
    await expect(client.verifyResponse('msg_fixture')).resolves.toMatchObject({
      signatureKind: 'gateway',
    });
    expect(fixture.requests).toHaveLength(1);
    expect(fixture.signatureCalls()).toBe(2);
  });

  test.each([false, true])(
    'rejects messages without a response ID (stream: %s)',
    async (streaming) => {
      const fixture = messagesGateway({ streaming, missingId: true });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      const response = await client.fetch(
        `${baseUrl}messages`,
        chatRequest({ input: 'Hello', stream: streaming }),
      );
      await expect(response.text()).rejects.toMatchObject({
        failure: { code: 'api.invalid_response' },
      });
    },
  );

  test('passes HTTP errors through without creating a receipt', async () => {
    const fixture = messagesGateway({ status: 400 });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    await expect(
      client.messages.create({
        model,
        messages: [{ role: 'user', content: 'Hello' }],
        max_tokens: 128,
      }),
    ).rejects.toMatchObject({ status: 400 });
    await expect(client.verifyResponse('msg_fixture')).rejects.toMatchObject({
      failure: { code: 'api.completion_not_found' },
    });
  });

  test('rejects E2EE, Direct, history and foreign URLs before network I/O', async () => {
    const fixture = messagesGateway();
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(fixture.fetch);
    const options = inferenceClientOptions(fixture.gateway);
    const plain = new InferenceClient({ ...options, e2ee: false });
    const encrypted = new InferenceClient(options);
    const direct = new DirectInferenceClient({ baseUrl, e2ee: false });
    for (const [client, url] of [
      [encrypted, `${baseUrl}messages`],
      [direct, `${baseUrl}messages`],
      [plain, `${baseUrl}messages/msg_fixture`],
      [plain, 'https://other.test/v1/messages'],
    ] as const) {
      await expect(
        client.fetch(url, chatRequest({ input: 'Hello' })),
      ).rejects.toMatchObject({ failure: { code: 'api.invalid_input' } });
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  const errorHeaderStream =
    'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_fixture"}}\n\nevent: error\ndata: {"type":"message_stop"}\n\n';

  test.each([
    errorHeaderStream,
    'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_fixture"}}\n\nevent:error\ndata: {"error":{"type":"overloaded_error"}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n',
    'event: message_start\r\ndata: {"type":"message_start","message":{"id":"msg_fixture"}}\r\n\r\nevent: ping\r\ndata: {"type":"message_stop"}\r\n\r\n',
    'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_fixture"}}\n\n',
    'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_fixture"}}\n\nevent: error\ndata: {"type":"error","error":{"type":"overloaded_error"}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n',
    'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_fixture"}}\n\nevent: message_stop\ndata: {"type":"message_stop"}',
    'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_fixture"}}\n\nevent: message_start\ndata: {"type":"message_start","message":{"id":"other"}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n',
  ])('does not verify incomplete or failed streams: %s', async (raw) => {
    const fixture = messagesGateway({
      streaming: true,
      rawBody: Buffer.from(raw),
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const response = await client.fetch(
      `${baseUrl}messages`,
      chatRequest({ stream: true }),
    );
    await response.text();
    await expect(client.verifyResponse('msg_fixture')).rejects.toMatchObject({
      failure: { code: 'api.invalid_response' },
    });
    expect(fixture.signatureCalls()).toBe(0);
    expect(fixture.requests).toHaveLength(1);
  });

  test('cannot verify after the Anthropic SDK rejects an error header', async () => {
    const fixture = messagesGateway({
      streaming: true,
      rawBody: Buffer.from(errorHeaderStream),
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const stream = await client.messages.create({
      model,
      max_tokens: 16,
      messages: [{ role: 'user', content: 'Hello' }],
      stream: true,
    });
    await expect(
      (async () => {
        for await (const event of stream) {
          expect(event.type).toBe('message_start');
        }
      })(),
    ).rejects.toBeInstanceOf(Anthropic.APIError);
    await expect(client.verifyResponse('msg_fixture')).rejects.toMatchObject({
      failure: { code: 'api.invalid_response' },
    });
    expect(fixture.signatureCalls()).toBe(0);
    expect(fixture.requests).toHaveLength(1);
  });

  test('preserves custom prefixes and Anthropic headers', async () => {
    const client = new InferenceClient({
      apiKey: 'test',
      baseUrl: 'https://gateway.test/custom/api/',
      headers: { 'anthropic-version': '2026-10-21' },
    });
    const fetch = jest
      .spyOn(client, 'fetch')
      .mockImplementation(async () =>
        jsonResponse({ id: 'msg_custom', type: 'message', content: [] }),
      );
    await client.messages.create(
      { model, max_tokens: 8, messages: [{ role: 'user', content: 'Hello' }] },
      {
        headers: {
          'anthropic-version': '2023-06-01',
          'anthropic-beta': 'test-beta',
        },
      },
    );
    const request = new Request(fetch.mock.calls[0][0]);
    expect(request.url).toBe('https://gateway.test/custom/api/messages');
    expect(request.headers.get('anthropic-beta')).toBe('test-beta');
    expect(request.headers.get('anthropic-version')).toBe('2023-06-01');
    await client.messages.create({
      model,
      max_tokens: 8,
      messages: [{ role: 'user', content: 'Hello' }],
    });
    const defaults = new Request(fetch.mock.calls[1][0]);
    expect(defaults.headers.get('anthropic-version')).toBe('2026-10-21');
  });

  test('does not verify a cancelled Messages stream', async () => {
    const fixture = messagesGateway({ streaming: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const response = await client.fetch(
      `${baseUrl}messages`,
      chatRequest({ stream: true }),
    );
    if (response.body === null) throw new Error('missing stream');
    const reader = response.body.getReader();
    await reader.read();
    await reader.cancel();
    await expect(client.verifyResponse('msg_fixture')).rejects.toBeDefined();
    expect(fixture.signatureCalls()).toBe(0);
  });
});

describe('ECDSA Messages adapters', () => {
  afterEach(() => jest.restoreAllMocks());
  for (const official of [false, true]) {
    for (const stream of [false, true] as const) {
      test(`ECDSA messages, official=${official}, stream=${stream}`, async () => {
        const gateway = createEcdsaGateway({ signatureKind: 'gateway' });
        const fetchSpy = jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation(gateway.fetch);
        const client = new InferenceClient({
          apiKey: 'key',
          baseUrl,
          signingAlgo: 'ecdsa',
          gatewayVerification: {
            verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
          },
          modelVerification: {
            verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
          },
        });
        const id = 'msg_fixture';
        const api = official
          ? new Anthropic({
              apiKey: 'key',
              baseURL: 'https://gateway.test',
              fetch: client.fetch,
              maxRetries: 0,
            })
          : client;
        const result = await api.messages.create({
          model,
          max_tokens: 128,
          messages: [{ role: 'user', content: 'Hello' }],
          stream,
        });
        if (Symbol.asyncIterator in result) {
          let text = '';
          for await (const event of result) {
            if (event.type === 'message_start')
              expect(event.message.id).toBe(id);
            if (
              event.type === 'content_block_delta' &&
              event.delta.type === 'text_delta'
            )
              text += event.delta.text;
          }
          expect(text).toContain('Hello');
        } else expect(result.id).toBe(id);
        const receipt = await client.verifyResponse(id);
        expect(receipt.signatureKind).toBe('gateway');
        expect(receipt.signature.signer.signingAlgo).toBe('ecdsa');
        fetchSpy.mockRestore();
      });
    }
  }
});
