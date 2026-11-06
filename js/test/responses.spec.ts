import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import OpenAI from 'openai';
import { ApiError, DirectInferenceClient, InferenceClient } from '../src';
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

describe('Responses API', () => {
  afterEach(() => jest.restoreAllMocks());

  function responsesGateway({
    streaming = false,
    tamper = false,
    providerReceipt = false,
    missingId = false,
    status = 200,
    retrySignature = false,
    tee = true,
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
            '../../test-fixtures/responses',
            streaming ? 'response.sse' : 'response.json',
          ),
        ),
    );
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === '/v1/responses') {
        gateway.expectRequestHeader(request);
        expect(gateway.state.gatewayAttestationRequests).toBeGreaterThan(0);
        expect(request.headers.get('x-no-aliasing')).toBe('true');
        expect(request.headers.has('x-client-pub-key')).toBe(false);
        expect(request.headers.has('x-model-pub-key')).toBe(tee);
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
            ? Buffer.from(raw.toString().replace('你好', '篡改'))
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
      if (url.pathname === '/v1/signature/resp_fixture') {
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

  test('clears Responses receipts and permits the same ID to be captured again', async () => {
    const fixture = responsesGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const request = { model, input: 'hello', store: false };
    const first = await client.responses.create(request);
    await client.verifyResponse(first.id);
    client.clearResponseCache();
    await expect(client.verifyResponse(first.id)).rejects.toMatchObject({
      failure: { code: 'api.completion_not_found' },
    });
    const next = await client.responses.create(request);
    await client.verifyResponse(next.id);
    client.clearResponseCache();
  });

  test.each(
    [false, true].flatMap((streaming) =>
      [false, true].flatMap((ohttp) =>
        [false, true].map((external) => ({
          streaming,
          ohttp,
          external,
          tee: !ohttp,
        })),
      ),
    ),
  )('creates and verifies exact bytes: %j', async (scenario) => {
    const fixture = responsesGateway(scenario);
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
    const responses = scenario.external
      ? new OpenAI({
          apiKey: 'external',
          baseURL: baseUrl,
          fetch: client.fetch,
        }).responses
      : client.responses;
    const input = [
      {
        type: 'function_call' as const,
        call_id: 'prior',
        name: 'weather',
        arguments: '{}',
      },
      {
        type: 'function_call_output' as const,
        call_id: 'prior',
        output: '{"temperature":20}',
      },
    ];
    if (scenario.streaming) {
      const events = [];
      const stream = await responses.create({
        model,
        input,
        store: false,
        stream: true,
      });
      for await (const event of stream) events.push(event);
      expect(events.map((event) => event.type)).toContain(
        'response.function_call_arguments.delta',
      );
      expect(events.at(-1)).toMatchObject({
        type: 'response.completed',
        response: { id: 'resp_fixture' },
      });
    } else {
      const response = await responses.create({ model, input, store: false });
      expect(response.id).toBe('resp_fixture');
      expect(response.output[2]).toMatchObject({
        type: 'function_call',
        arguments: '{"city":"北京"}',
      });
    }
    expect(await fixture.requests[0].json()).toMatchObject({
      input,
      store: false,
    });
    await expect(client.verifyResponse('resp_fixture')).resolves.toMatchObject({
      id: 'resp_fixture',
      signatureKind: 'gateway',
    });
    await expect(client.verifyResponse('msg_1')).rejects.toMatchObject({
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

  test('preserves Node TLS pinning for Responses', async () => {
    const fixture = responsesGateway();
    mockNodeGatewayAttestation({ gateway: fixture.gateway });
    const client = new TestNodeInferenceClient(
      { ...inferenceClientOptions(fixture.gateway), e2ee: false },
      fixture.fetch,
    );
    const response = await client.responses.create({ model, input: 'Hello' });
    await expect(client.verifyResponse(response.id)).resolves.toMatchObject({
      signatureKind: 'gateway',
    });
    expect(client.pinnedSpkiFingerprints).toEqual([tlsFingerprint]);
  });

  test.each([false, true])(
    'rejects tampered bytes (stream: %s)',
    async (streaming) => {
      const fixture = responsesGateway({ streaming, tamper: true });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      const response = await client.fetch(
        `${baseUrl}responses`,
        chatRequest({ input: 'Hello', stream: streaming }),
      );
      await response.text();
      await expect(client.verifyResponse('resp_fixture')).rejects.toMatchObject(
        { failure: { code: 'signature.payload_mismatch' } },
      );
    },
  );

  test('requires a Gateway receipt even when model evidence was verified', async () => {
    const fixture = responsesGateway({ providerReceipt: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    await client.responses.create({ model, input: 'Hello' });
    await expect(client.verifyResponse('resp_fixture')).rejects.toMatchObject({
      failure: { code: 'signature.kind_mismatch' },
    });
  });

  test('retries signature lookup without repeating inference', async () => {
    const fixture = responsesGateway({ retrySignature: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    await client.responses.create({ model, input: 'Hello' });
    await expect(client.verifyResponse('resp_fixture')).rejects.toMatchObject({
      failure: { code: 'api.http_status' },
    });
    await expect(client.verifyResponse('resp_fixture')).resolves.toMatchObject({
      signatureKind: 'gateway',
    });
    expect(fixture.requests).toHaveLength(1);
    expect(fixture.signatureCalls()).toBe(2);
  });

  const responseStreamCases: { name: string; body: string; valid: boolean }[] =
    JSON.parse(
      readFileSync(
        resolve(__dirname, '../../test-fixtures/responses/streams.json'),
        'utf8',
      ),
    );
  test.each(responseStreamCases)(
    'Responses stream contract: $name',
    async (scenario) => {
      const fixture = responsesGateway({
        streaming: true,
        rawBody: Buffer.from(scenario.body),
      });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      let body: string | undefined;
      try {
        const response = await client.fetch(
          `${baseUrl}responses`,
          chatRequest({ input: 'Hello', stream: true }),
        );
        body = await response.text();
      } catch (error) {
        if (scenario.valid) throw error;
        expect(error).toBeInstanceOf(ApiError);
      }
      if (scenario.valid) {
        expect(body).toBe(scenario.body);
        await expect(
          client.verifyResponse('resp_fixture'),
        ).resolves.toMatchObject({ signatureKind: 'gateway' });
        expect(fixture.signatureCalls()).toBe(1);
      } else {
        await expect(
          client.verifyResponse('resp_fixture'),
        ).rejects.toBeInstanceOf(ApiError);
        expect(fixture.signatureCalls()).toBe(0);
      }
      expect(fixture.requests).toHaveLength(1);
    },
  );

  test('rejects a JSON response without a response ID', async () => {
    const fixture = responsesGateway({ missingId: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const response = await client.fetch(
      `${baseUrl}responses`,
      chatRequest({ input: 'Hello' }),
    );
    await expect(response.text()).rejects.toMatchObject({
      failure: { code: 'api.invalid_response' },
    });
    await expect(client.verifyResponse('resp_fixture')).rejects.toMatchObject({
      failure: { code: 'api.completion_not_found' },
    });
    expect(fixture.signatureCalls()).toBe(0);
  });

  test('passes HTTP errors through without creating a receipt', async () => {
    const fixture = responsesGateway({ status: 400 });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    await expect(
      client.responses.create({ model, input: 'Hello' }),
    ).rejects.toMatchObject({ status: 400 });
    await expect(client.verifyResponse('resp_fixture')).rejects.toMatchObject({
      failure: { code: 'api.completion_not_found' },
    });
  });

  test('rejects E2EE, Direct, history and foreign URLs before network I/O', async () => {
    const fixture = responsesGateway();
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(fixture.fetch);
    const options = inferenceClientOptions(fixture.gateway);
    const plain = new InferenceClient({ ...options, e2ee: false });
    const encrypted = new InferenceClient(options);
    const direct = new DirectInferenceClient({ baseUrl, e2ee: false });
    for (const [client, url] of [
      [encrypted, `${baseUrl}responses`],
      [direct, `${baseUrl}responses`],
      [plain, `${baseUrl}responses/resp_fixture`],
      [plain, 'https://other.test/v1/responses'],
    ] as const) {
      await expect(
        client.fetch(url, chatRequest({ input: 'Hello' })),
      ).rejects.toMatchObject({ failure: { code: 'api.invalid_input' } });
    }
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('ECDSA Responses adapters', () => {
  afterEach(() => jest.restoreAllMocks());
  for (const official of [false, true]) {
    for (const stream of [false, true] as const) {
      test(`ECDSA responses, official=${official}, stream=${stream}`, async () => {
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
        const id = 'resp_fixture';
        const api = official
          ? new OpenAI({
              apiKey: 'key',
              baseURL: baseUrl,
              fetch: client.fetch,
              maxRetries: 0,
            })
          : client;
        const result = await api.responses.create({
          model,
          input: 'Hello',
          store: false,
          stream,
        });
        if (Symbol.asyncIterator in result) {
          let text = '';
          for await (const event of result) {
            if (event.type === 'response.created')
              expect(event.response.id).toBe(id);
            if (event.type === 'response.output_text.delta')
              text += event.delta;
          }
          expect(text).toContain('你好');
        } else expect(result.id).toBe(id);
        const receipt = await client.verifyResponse(id);
        expect(receipt.signatureKind).toBe('gateway');
        expect(receipt.signature.signer.signingAlgo).toBe('ecdsa');
        fetchSpy.mockRestore();
      });
    }
  }
});
