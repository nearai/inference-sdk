import { Buffer } from 'node:buffer';
import OpenAI from 'openai';
import nacl from 'tweetnacl';
import {
  type AttestationVerificationResult,
  InferenceClient,
  type InferenceClientOptions,
  VerificationError,
} from '../src';
import {
  AttestationClient as NodeAttestationClient,
  InferenceClient as NodeInferenceClient,
} from '../src/node';
import { createEcdsaGateway, modelPublicKey } from './ecdsa-gateway-fixtures';
import { appCompose, tlsFingerprint } from './fixtures';
import type { TestGateway } from './inference-client-fixtures';
import {
  aggregatorHeader,
  baseUrl,
  chatRequest,
  createSignatureFetch,
  createTestGateway,
  encryptE2eeText,
  eventLog,
  inferenceClientOptions,
  jsonResponse,
  keyHex,
  keyPair,
  mockNodeGatewayAttestation,
  model,
  type NodeAttestationClientPrototype,
  retainedCapture,
  TestNodeInferenceClient,
} from './inference-client-fixtures';
import { createOhttpEndpoint } from './ohttp-fixtures';

const secondModel = 'qwen-3.5';

const directApiKey = 'direct-api-key';

function mockProviderSignatures(gateway: TestGateway): void {
  jest
    .spyOn(globalThis, 'fetch')
    .mockImplementation(createSignatureFetch(gateway));
}

function isChatCompletionRequest(input: RequestInfo | URL): boolean {
  const url = input instanceof Request ? input.url : input.toString();
  return new URL(url).pathname === '/v1/chat/completions';
}

describe('inference client', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  test('uses pinned OHTTP for JSON and SSE while retaining evidence, signatures and session reuse', async () => {
    const gateway = createTestGateway();
    const endpoint = await createOhttpEndpoint({
      fetch: createSignatureFetch(gateway),
      signingKey: keyPair(1),
    });
    mockNodeGatewayAttestation({
      gateway: { ...gateway, fetch: endpoint.fetch },
    });
    const pinnedFetch = jest.fn(endpoint.fetch);
    const rawFetch = jest.spyOn(globalThis, 'fetch');
    const client = new TestNodeInferenceClient(
      {
        ...inferenceClientOptions(gateway),
        ohttp: true,
        signingAlgo: 'ed25519',
      },
      pinnedFetch,
    );

    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello JSON' }],
    });
    expect(completion.choices[0].message.content).toBe('hello client');
    await expect(client.verifyResponse(completion.id)).resolves.toMatchObject({
      id: completion.id,
      signatureKind: 'provider_tee',
    });
    const stream = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello SSE' }],
      stream: true,
    });
    let id = '';
    let content = '';
    for await (const event of stream) {
      id = event.id;
      content += event.choices[0]?.delta.content ?? '';
    }
    expect(content).toBe('hello client');
    await expect(client.verifyResponse(id)).resolves.toMatchObject({
      id,
      signatureKind: 'provider_tee',
    });
    expect(gateway.state.decryptedRequestContent).toEqual([
      'hello JSON',
      'hello SSE',
    ]);
    expect(gateway.state.gatewayAttestationRequests).toBe(1);
    expect(gateway.state.modelAttestationRequests).toBe(1);
    expect(client.pinnedSpkiFingerprints).toEqual([tlsFingerprint]);
    expect(rawFetch).not.toHaveBeenCalled();
    const pinnedPaths = pinnedFetch.mock.calls.map(
      ([request]) => new URL((request as Request).url).pathname,
    );
    expect(pinnedPaths).toEqual([
      `/v1/model/${model}`,
      '/v1/attestation/report',
      '/ohttp',
      `/v1/signature/${completion.id}`,
      '/ohttp',
      `/v1/signature/${id}`,
    ]);
    for (const request of endpoint.requests) {
      expect(request.headers.get(aggregatorHeader.name)).toBe(
        aggregatorHeader.value,
      );
      if (new URL(request.url).pathname === '/ohttp') {
        expect(request.headers.get('content-type')).toBe(
          'message/ohttp-chunked-req',
        );
        expect(request.headers.has('x-model-pub-key')).toBe(false);
      }
    }
  });

  describe.each(['browser', 'Node'] as const)(
    '%s OHTTP preflight',
    (runtime) => {
      test.each(['missing', 'model-signed', 'malformed-config'] as const)(
        'rejects %s Gateway evidence before authenticated requests',
        async (evidence) => {
          const gateway = createTestGateway();
          const endpoint = await createOhttpEndpoint({
            fetch: gateway.fetch,
            signingKey: keyPair(evidence === 'model-signed' ? 2 : 1),
            attestedKeyConfig:
              evidence === 'malformed-config' ? new Uint8Array([0]) : undefined,
          });
          const fetch = evidence === 'missing' ? gateway.fetch : endpoint.fetch;
          jest.spyOn(globalThis, 'fetch').mockImplementation(fetch);
          if (runtime === 'Node') {
            mockNodeGatewayAttestation({ gateway: { ...gateway, fetch } });
          }
          const options: InferenceClientOptions = {
            ...inferenceClientOptions(gateway),
            ohttp: true,
            signingAlgo: 'ed25519',
          };
          const client =
            runtime === 'Node'
              ? new TestNodeInferenceClient(options, fetch)
              : new InferenceClient(options);
          const verification = client.verify(model);
          const completion = client.fetch(
            `${baseUrl}chat/completions`,
            chatRequest({ messages: [] }),
          );
          const expectedError = {
            failure: {
              code: {
                missing: 'ohttp.attestation_required',
                'model-signed': 'ohttp.signer_mismatch',
                'malformed-config': 'ohttp.key_config_invalid',
              }[evidence],
            },
          };
          await Promise.all([
            expect(verification).rejects.toMatchObject(expectedError),
            expect(completion).rejects.toMatchObject(expectedError),
          ]);
          expect(gateway.state.gatewayAttestationRequests).toBe(1);
          expect(gateway.state.metadataModels).toEqual([]);
          expect(gateway.state.modelAttestationRequests).toBe(0);
          expect(gateway.state.completionRequests).toBe(0);
          expect(
            endpoint.requests.every(
              (request) => new URL(request.url).pathname !== '/ohttp',
            ),
          ).toBe(true);
        },
      );
    },
  );

  test('calls browser Fetch with the global receiver', async () => {
    const gateway = createTestGateway();
    const providerFetch = createSignatureFetch(gateway);
    jest.spyOn(globalThis, 'fetch').mockImplementation(function (
      this: typeof globalThis | undefined,
      input,
      init,
    ) {
      // Browser Fetch accepts a standalone call, but not an arbitrary receiver.
      if (this !== undefined && this !== globalThis) {
        throw new TypeError('Illegal invocation');
      }
      return providerFetch(input, init);
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));
    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello' }],
    });
    await expect(client.verifyResponse(completion.id)).resolves.toMatchObject({
      id: completion.id,
    });
  });

  test('reuses one OpenAI client for concurrent JSON and streaming responses', async () => {
    const gateway = createTestGateway();
    mockProviderSignatures(gateway);
    const inferenceClient = new InferenceClient(
      inferenceClientOptions(gateway),
    );
    const openai = new OpenAI({
      apiKey: directApiKey,
      baseURL: baseUrl,
      fetch: inferenceClient.fetch,
    });
    const [completion, stream] = await Promise.all([
      openai.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'first' }],
      }),
      openai.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'second' }],
        stream: true,
      }),
    ]);
    let streamId = '';
    let streamVerification: Promise<unknown> | undefined;
    for await (const chunk of stream) {
      streamId = chunk.id;
      // The ID is registered before the first chunk reaches the caller.
      streamVerification ??= inferenceClient.verifyResponse(streamId);
    }
    await expect(streamVerification).resolves.toMatchObject({
      id: streamId,
    });
    const verification = inferenceClient.verifyResponse(completion.id);
    expect(inferenceClient.verifyResponse(completion.id)).toBe(verification);
    await expect(verification).resolves.toMatchObject({
      id: completion.id,
    });
    expect(inferenceClient.verifyResponse(completion.id)).toBe(verification);
  });

  test.each(['chat/completions', 'responses'])(
    'rejects %s [DONE] without an ID before exposing it',
    async (endpoint) => {
      const gateway = createTestGateway();
      const payload =
        endpoint === 'responses'
          ? { response: { id: 'late-id' } }
          : { id: 'late-id' };
      const records = [
        'data: [DONE]\n\n',
        `data: ${JSON.stringify(payload)}\n\n`,
      ];
      jest.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const request = new Request(input, init);
        return new URL(request.url).pathname === `/v1/${endpoint}`
          ? Promise.resolve(streamResponse(records))
          : gateway.fetch(request);
      });
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        e2ee: false,
      });
      const response = await client.fetch(
        `${baseUrl}${endpoint}`,
        chatRequest({ messages: [], input: 'Hello', stream: true }),
      );
      await expect(response.body?.getReader().read()).rejects.toMatchObject({
        failure: { code: 'api.invalid_response' },
      });
      await expect(client.verifyResponse('late-id')).rejects.toMatchObject({
        failure: { code: 'api.completion_not_found' },
      });
    },
  );

  test.each([
    ['default', undefined, 60 * 60 * 1000],
    ['custom', 1000, 1000],
    ['long', 2 ** 31, 2 ** 31],
  ] as const)(
    'expires response records at the %s TTL independently of the attestation cache',
    async (_label, responseCacheTimeToLiveMs, expectedTtl) => {
      const gateway = createTestGateway();
      mockProviderSignatures(gateway);
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        responseCacheTimeToLiveMs,
      });
      jest.useFakeTimers({
        doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'],
      });
      const completion = await client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello' }],
      });
      jest.advanceTimersByTime(expectedTtl - 1);
      await client.verifyResponse(completion.id);
      await expect(client.verifyResponse(completion.id)).resolves.toMatchObject(
        {
          id: completion.id,
        },
      );
      jest.advanceTimersByTime(1);
      await expect(client.verifyResponse(completion.id)).rejects.toMatchObject({
        failure: { code: 'api.completion_not_found' },
      });
    },
  );

  test.each([
    [false, false],
    [false, true],
    [true, false],
    [true, true],
  ])(
    'releases verified bodies while retaining the result (TEE=%s, stream=%s)',
    async (tee, streaming) => {
      const gateway = createTestGateway({
        providerType: tee ? 'vllm' : 'openai',
        attestationSupported: tee,
      });
      const fetch = createSignatureFetch(
        gateway,
        tee ? 'provider_tee' : 'gateway',
      );
      let signatureRequests = 0;
      jest.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const request = new Request(input, init);
        if (new URL(request.url).pathname.startsWith('/v1/signature/')) {
          signatureRequests++;
        }
        return fetch(request);
      });
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        e2ee: tee,
      });
      const request = {
        model,
        messages: [{ role: 'user' as const, content: 'hello' }],
      };
      let id = '';
      if (streaming) {
        const stream = await client.chat.completions.create({
          ...request,
          stream: true,
        });
        for await (const chunk of stream) id = chunk.id;
      } else {
        id = (await client.chat.completions.create(request)).id;
      }
      expect(retainedCapture(client, id)).toBeDefined();
      const verification = client.verifyResponse(id);
      expect(client.verifyResponse(id)).toBe(verification);
      expect(retainedCapture(client, id)).toBeDefined();
      const result = await verification;
      expect(retainedCapture(client, id)).toBeUndefined();
      expect(client.verifyResponse(id)).toBe(verification);
      expect(await client.verifyResponse(id)).toBe(result);
      expect(signatureRequests).toBe(1);
      client.clearResponseCache();
    },
  );

  test.each([false, true])(
    'clears response bytes and expiry timers while preserving the session (TEE=%s)',
    async (tee) => {
      const gateway = createTestGateway({
        providerType: tee ? 'vllm' : 'openai',
        attestationSupported: tee,
      });
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(
          createSignatureFetch(gateway, tee ? 'provider_tee' : 'gateway'),
        );
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        e2ee: tee,
      });
      jest.useFakeTimers({
        doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'],
      });
      const request = {
        model,
        messages: [{ role: 'user' as const, content: 'hello' }],
      };
      const first = await client.chat.completions.create(request);
      await client.verifyResponse(first.id);
      expect(jest.getTimerCount()).toBe(1);

      client.clearResponseCache();
      client.clearResponseCache();
      expect(jest.getTimerCount()).toBe(0);
      await expect(client.verifyResponse(first.id)).rejects.toMatchObject({
        failure: { code: 'api.completion_not_found' },
      });

      const next = await client.chat.completions.create(request);
      await expect(client.verifyResponse(next.id)).resolves.toMatchObject({
        id: next.id,
      });
      expect(gateway.state.gatewayAttestationRequests).toBe(1);
      expect(gateway.state.modelAttestationRequests).toBe(tee ? 1 : 0);
      client.clearResponseCache();
      expect(jest.getTimerCount()).toBe(0);
    },
  );

  test('does not retain a response that arrives after the cache was cleared', async () => {
    const gateway = createTestGateway();
    const fetch = createSignatureFetch(gateway);
    let resumeResponse!: () => void;
    let responseReady!: () => void;
    const resume = new Promise<void>((resolve) => {
      resumeResponse = resolve;
    });
    const ready = new Promise<void>((resolve) => {
      responseReady = resolve;
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const response = await fetch(input, init);
      if (isChatCompletionRequest(input)) {
        responseReady();
        await resume;
      }
      return response;
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));
    const completion = client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello' }],
    });
    await ready;
    client.clearResponseCache();
    resumeResponse();
    const result = await completion;
    expect(result.choices[0].message.content).toBe('hello client');
    await expect(client.verifyResponse(result.id)).rejects.toMatchObject({
      failure: { code: 'api.completion_not_found' },
    });
  });

  test.each([
    'attestationCacheTimeToLiveMs',
    'responseCacheTimeToLiveMs',
  ] as const)(
    'rejects invalid durations for %s before network access',
    (field) => {
      const network = jest.spyOn(globalThis, 'fetch');
      for (const value of [
        -1,
        Number.NaN,
        Number.POSITIVE_INFINITY,
        Number.NEGATIVE_INFINITY,
      ]) {
        expect(
          () => new InferenceClient({ apiKey: directApiKey, [field]: value }),
        ).toThrow(
          expect.objectContaining({
            failure: expect.objectContaining({
              code: 'api.invalid_input',
              details: expect.objectContaining({ field }),
            }),
          }),
        );
      }
      expect(network).not.toHaveBeenCalled();
    },
  );

  test.each([404, 503])(
    'retries response verification after HTTP %i',
    async (status) => {
      const gateway = createTestGateway();
      const providerFetch = createSignatureFetch(gateway);
      let signatureRequests = 0;
      jest.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const request = new Request(input, init);
        if (new URL(request.url).pathname.startsWith('/v1/signature/')) {
          signatureRequests += 1;
          if (signatureRequests === 1) {
            return Promise.resolve(new Response('try again', { status }));
          }
        }
        return providerFetch(request);
      });
      const client = new InferenceClient(inferenceClientOptions(gateway));
      const completion = await client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello' }],
      });

      const firstAttempt = client.verifyResponse(completion.id);
      expect(client.verifyResponse(completion.id)).toBe(firstAttempt);
      await expect(firstAttempt).rejects.toMatchObject({
        failure: { code: 'api.http_status', details: { status } },
        retryable: true,
      });
      expect(retainedCapture(client, completion.id)).toBeDefined();

      const retry = client.verifyResponse(completion.id);
      expect(client.verifyResponse(completion.id)).toBe(retry);
      await expect(retry).resolves.toMatchObject({
        id: completion.id,
      });
      expect(client.verifyResponse(completion.id)).toBe(retry);
      expect(signatureRequests).toBe(2);
      expect(retainedCapture(client, completion.id)).toBeUndefined();
    },
  );

  test('preserves proxy authorization with an external OpenAI client', async () => {
    const authorization = 'Bearer proxy-token';
    const gateway = createTestGateway({
      expectedRequestHeader: { name: 'authorization', value: authorization },
    });
    mockProviderSignatures(gateway);
    const inferenceClient = new InferenceClient({
      ...inferenceClientOptions(gateway),
      headers: { Authorization: authorization },
    });
    const openai = new OpenAI({
      apiKey: 'unused-placeholder',
      baseURL: baseUrl,
      fetch: inferenceClient.fetch,
      maxRetries: 0,
    });

    const completion = await openai.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello' }],
    });
    await expect(
      inferenceClient.verifyResponse(completion.id),
    ).resolves.toMatchObject({
      id: completion.id,
    });
  });

  test.each([true, false])(
    'uses header-only authentication with an external OpenAI client and e2ee=%s',
    async (e2ee) => {
      const gateway = createTestGateway({
        expectedRequestHeader: { name: 'x-api-key', value: 'proxy-key' },
      });
      const providerFetch = createSignatureFetch(gateway);
      const requests: Request[] = [];
      jest.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const request = new Request(input, init);
        requests.push(request);
        return providerFetch(request);
      });
      const inferenceClient = new InferenceClient({
        ...inferenceClientOptions(gateway),
        headers: { 'X-API-Key': 'proxy-key' },
        e2ee,
      });
      const openai = new OpenAI({
        apiKey: 'unused-placeholder',
        baseURL: baseUrl,
        fetch: inferenceClient.fetch,
        maxRetries: 0,
      });

      const completion = await openai.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello' }],
      });
      const verified = await inferenceClient.verifyResponse(completion.id);

      expect(verified.id).toBe(completion.id);
      expect(verified.completionId).toBe(completion.id);
      for (const request of requests) {
        expect(request.headers.has('authorization')).toBe(false);
      }
    },
  );

  test('verifies the successful response after an OpenAI retry', async () => {
    const gateway = createTestGateway();
    const providerFetch = createSignatureFetch(gateway);
    let attempts = 0;
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (isChatCompletionRequest(input) && attempts++ === 0) {
        return new Response('retry', {
          status: 503,
          headers: { 'retry-after-ms': '1' },
        });
      }
      return providerFetch(input, init);
    });
    const inferenceClient = new InferenceClient(
      inferenceClientOptions(gateway),
    );
    const openai = new OpenAI({
      apiKey: directApiKey,
      baseURL: baseUrl,
      fetch: inferenceClient.fetch,
    });
    const completion = await openai.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello' }],
    });
    expect(attempts).toBe(2);
    await expect(
      inferenceClient.verifyResponse(completion.id),
    ).resolves.toMatchObject({ id: completion.id });
  });

  test.each([undefined, directApiKey])(
    'supports optional Gateway API key %s',
    async (apiKey) => {
      const gateway = createTestGateway({
        expectedRequestHeader: {
          name: 'authorization',
          value: apiKey === undefined ? null : `Bearer ${apiKey}`,
        },
      });
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      const client = new InferenceClient({
        apiKey,
        baseUrl,
        gatewayVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
        modelVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
      });

      await client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      );

      expect(gateway.state).toMatchObject({
        gatewayAttestationRequests: 1,
        modelAttestationRequests: 1,
        completionRequests: 1,
      });
      expect(gateway.state.gatewayAttestationIncludeSpkiFingerprints).toEqual([
        false,
      ]);
    },
  );

  test.each([true, false])(
    'preverifies without Chat and reuses evidence for 60 minutes (TEE: %s)',
    async (attestationSupported) => {
      const gateway = createTestGateway({ attestationSupported });
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      const now = jest.spyOn(Date, 'now').mockReturnValue(0);
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        e2ee: attestationSupported,
      });

      const result: AttestationVerificationResult = await client.verify(model);
      expect(result).toMatchObject({
        verifiedAt: 0,
        gateway: { tcbStatus: 'UpToDate', tlsBinding: { kind: 'none' } },
      });
      expect(result.models).toHaveLength(attestationSupported ? 1 : 0);
      expect(gateway.state).toMatchObject({
        gatewayAttestationRequests: 1,
        modelAttestationRequests: attestationSupported ? 1 : 0,
        completionRequests: 0,
      });
      now.mockReturnValue(42);
      const cached = await client.verify(model);
      expect(cached).toEqual(result);
      now.mockReturnValue(60 * 60 * 1000 - 1);
      await client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello model' }],
      });
      expect(gateway.state).toMatchObject({
        gatewayAttestationRequests: 1,
        metadataModels: [model],
        modelAttestationRequests: attestationSupported ? 1 : 0,
        completionRequests: 1,
      });
      now.mockReturnValue(60 * 60 * 1000);
      await client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({
          messages: [{ role: 'user', content: 'refresh evidence' }],
        }),
      );
      expect(gateway.state).toMatchObject({
        gatewayAttestationRequests: 2,
        metadataModels: [model, model],
        modelAttestationRequests: attestationSupported ? 2 : 0,
        completionRequests: 2,
      });
      const refreshed = await client.verify(model);
      expect(refreshed.verifiedAt).toBe(60 * 60 * 1000);
      expect(refreshed.gateway.report.nonce).not.toBe(
        result.gateway.report.nonce,
      );
      expect(gateway.state.gatewayAttestationRequests).toBe(2);
    },
  );

  test('verifies every request when the attestation cache time-to-live is zero', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      attestationCacheTimeToLiveMs: 0,
    });

    await client.verify(model);
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello again' }] }),
    );

    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 3,
      modelAttestationRequests: 3,
      completionRequests: 2,
    });
  });

  test('refreshes verified evidence after its cache time-to-live expires', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const now = jest.spyOn(Date, 'now').mockReturnValue(0);
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      attestationCacheTimeToLiveMs: 100,
    });

    await client.verify(model);
    now.mockReturnValue(100);
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello again' }] }),
    );

    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 2,
      modelAttestationRequests: 2,
      completionRequests: 1,
    });
  });

  test('verifies the requested model and passes it to the deployment policy', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const policyModels: string[] = [];
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      deploymentPolicy: ({ model: policyModel }) => {
        policyModels.push(policyModel);
      },
    });

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'first model' }] }),
    );
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        model: secondModel,
        messages: [{ role: 'user', content: 'second model' }],
      }),
    );

    expect(gateway.state.modelAttestationModels).toEqual([model, secondModel]);
    expect(policyModels).toEqual([model, secondModel]);
  });

  test('supports a model deployment verifier without a deployment policy', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const deployment = jest.fn();
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      modelVerification: {
        verifiers: { tdxQuote: gateway.tdxQuoteVerifier, deployment },
      },
    });

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    expect(deployment).toHaveBeenCalledTimes(1);
    expect(deployment).toHaveBeenCalledWith({
      appCompose,
      runtimeMeasurements: expect.any(Object),
    });
    expect(gateway.state.completionRequests).toBe(1);
  });

  test('awaits the model deployment verifier before the policy and Chat', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const calls: string[] = [];
    const deployment = jest.fn(async () => {
      calls.push('verifier started');
      await Promise.resolve();
      calls.push('verifier finished');
    });
    const deploymentPolicy = jest.fn(async () => {
      expect(calls).toEqual(['verifier started', 'verifier finished']);
      calls.push('policy started');
      await Promise.resolve();
      calls.push('policy finished');
      expect(gateway.state.completionRequests).toBe(0);
    });
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      modelVerification: {
        verifiers: { tdxQuote: gateway.tdxQuoteVerifier, deployment },
      },
      deploymentPolicy,
    });

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );
    expect(deploymentPolicy).toHaveBeenCalledWith({
      model,
      deployment: { appCompose, runtimeMeasurements: expect.any(Object) },
    });
    expect(calls).toEqual([
      'verifier started',
      'verifier finished',
      'policy started',
      'policy finished',
    ]);
    expect(gateway.state.completionRequests).toBe(1);
  });

  test('caches verified sessions by exact model', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await client.verify(model);
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        model: secondModel,
        messages: [{ role: 'user', content: 'second model' }],
      }),
    );
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [{ role: 'user', content: 'first model again' }],
      }),
    );

    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 2,
      modelAttestationRequests: 2,
      completionRequests: 2,
    });
    expect(gateway.state.modelAttestationModels).toEqual([model, secondModel]);
  });

  test('keeps concurrent verification separate for different models', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await Promise.all([
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'first model' }] }),
      ),
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({
          model: secondModel,
          messages: [{ role: 'user', content: 'second model' }],
        }),
      ),
    ]);

    expect(gateway.state.modelAttestationModels).toEqual(
      expect.arrayContaining([model, secondModel]),
    );
    expect(gateway.state.modelAttestationRequests).toBe(2);
  });

  test('shares concurrent verification between verify and Chat for the same model', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const [first, second] = await Promise.all([
      client.verify(model),
      client.verify(model),
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'first request' }] }),
      ),
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({
          messages: [{ role: 'user', content: 'second request' }],
        }),
      ),
    ]);

    expect(second).toEqual(first);
    expect(first.models).toHaveLength(1);
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 2,
    });
  });

  test.each(['gatewayVerification', 'modelVerification'] as const)(
    'does not cache rejected preverification from %s',
    async (verificationOptions) => {
      const gateway = createTestGateway();
      mockProviderSignatures(gateway);
      const tdxQuote = jest
        .fn(gateway.tdxQuoteVerifier)
        .mockImplementationOnce(() => {
          throw new Error('quote rejected');
        });
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        [verificationOptions]: { verifiers: { tdxQuote } },
      });

      await expect(client.verify(model)).rejects.toMatchObject({
        failure: { code: 'quote.verification_failed' },
      });
      expect(gateway.state.completionRequests).toBe(0);

      await client.verify(model);
      const completion = await client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello model' }],
      });
      const verified = await client.verifyResponse(completion.id);
      expect(verified.signatureKind).toBe('provider_tee');
      expect(tdxQuote).toHaveBeenCalledTimes(2);
      expect(gateway.state.gatewayAttestationRequests).toBe(2);
      expect(gateway.state.completionRequests).toBe(1);
    },
  );

  test('aborts one caller without cancelling shared attestation verification', async () => {
    const gateway = createTestGateway();
    let gatewayAttestationRequest: Request | undefined;
    let resolveGatewayAttestation: (response: Response) => void = () => {};
    const gatewayAttestationResponse = new Promise<Response>((resolve) => {
      resolveGatewayAttestation = resolve;
    });
    let notifyGatewayAttestationStarted: () => void = () => {};
    const gatewayAttestationStarted = new Promise<void>((resolve) => {
      notifyGatewayAttestationStarted = resolve;
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (
        url.pathname === '/v1/attestation/report' &&
        !url.searchParams.has('model')
      ) {
        gatewayAttestationRequest = request;
        notifyGatewayAttestationStarted();
        return gatewayAttestationResponse;
      }
      return gateway.fetch(request);
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));
    const controller = new AbortController();

    const aborted = client.fetch(`${baseUrl}chat/completions`, {
      ...chatRequest({ messages: [{ role: 'user', content: 'cancel me' }] }),
      signal: controller.signal,
    });
    await gatewayAttestationStarted;

    const succeeding = client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'still send me' }] }),
    );
    controller.abort();

    await expect(aborted).rejects.toMatchObject({ name: 'AbortError' });
    if (gatewayAttestationRequest === undefined) {
      throw new Error('Expected a Gateway attestation request');
    }
    resolveGatewayAttestation(await gateway.fetch(gatewayAttestationRequest));

    await expect(succeeding).resolves.toBeInstanceOf(Response);
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 1,
    });
  });

  test('rejects an empty model before preverification makes any network requests', async () => {
    const gateway = createTestGateway();
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await expect(client.verify('')).rejects.toMatchObject({
      failure: {
        code: 'api.invalid_input',
        details: { field: 'model', reason: 'missing_model' },
      },
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  test('requires a model before it fetches attestation evidence', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await expect(
      client.fetch(`${baseUrl}chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          messages: [{ role: 'user', content: 'hello model' }],
        }),
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'api.invalid_input',
        details: { field: 'request body' },
      },
    });
    expect(gateway.state.gatewayAttestationRequests).toBe(0);
    expect(gateway.state.modelAttestationRequests).toBe(0);
  });

  test('blocks an E2EE request when model evidence has no signing public key', async () => {
    const gateway = createTestGateway({ includeModelPublicKey: false });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await expect(
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      ),
    ).rejects.toMatchObject({
      failure: { code: 'e2ee.model_public_key_required' },
    });
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 0,
    });
  });

  test('fetch verifies, encrypts, and decrypts a Chat Completions request', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [{ message: { content: 'hello client' } }],
    });
    expect(gateway.state.decryptedRequestContent).toEqual(['hello model']);
    expect(
      gateway.state.completionRequestsSeen[0].headers.get('x-model-pub-key'),
    ).toEqual(expect.any(String));
  });

  test('encrypts assistant context fields when present', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [
          { role: 'user', content: 'Continue the prior conversation.' },
          {
            role: 'assistant',
            content: null,
            reasoning_content: 'A private intermediate explanation.',
            reasoning: 'A private reasoning summary.',
            audio: { format: 'wav', data: 'private audio bytes' },
          },
        ],
      }),
    );

    expect(gateway.state.decryptedRequestReasoningContent).toEqual([
      'A private intermediate explanation.',
    ]);
    expect(gateway.state.decryptedRequestReasoning).toEqual([
      'A private reasoning summary.',
    ]);
    expect(gateway.state.decryptedRequestAudio).toEqual([
      'private audio bytes',
    ]);
  });

  test('replaces a caller content length after encrypting the request body', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));
    const request = new Request(`${baseUrl}chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': '1',
      },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: 'hello model' }],
      }),
    });

    await client.fetch(request);

    expect(
      gateway.state.completionRequestsSeen[0].headers.get('content-length'),
    ).toBeNull();
  });

  test('skips a report without a public key and retains the selected nonadjacent signer group', async () => {
    const gateway = createTestGateway({ includeSecondModelAttestation: true });
    const fetch = createSignatureFetch(gateway);
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const request = new Request(input, init);
      const response = await fetch(request);
      const url = new URL(request.url);
      if (
        url.pathname === '/v1/attestation/report' &&
        url.searchParams.has('model')
      ) {
        const body = await response.json();
        body.model_attestations.push(body.model_attestations[0]);
        body.model_attestations.unshift({
          ...body.model_attestations[1],
          signing_public_key: null,
        });
        return jsonResponse(body);
      }
      return response;
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const result = await client.verify(model);
    expect(result.models.map(({ signer }) => signer.signingAddress)).toEqual([
      keyHex(keyPair(3).publicKey),
      keyHex(keyPair(2).publicKey),
      keyHex(keyPair(3).publicKey),
      keyHex(keyPair(2).publicKey),
    ]);
    for (const attestation of [result.gateway, ...result.models]) {
      expect(attestation.report).toMatchObject({
        signer: attestation.signer,
        intelQuote: `${attestation.signer.signingAddress}:${attestation.report.nonce}`,
        eventLog,
        appCompose: attestation.deployment.appCompose,
      });
    }

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [{ message: { content: 'hello client' } }],
    });
    expect(gateway.state.decryptedRequestContent).toEqual(['hello model']);
    expect(gateway.state.modelAttestationRequests).toBe(1);
    const receipt = await client.verifyResponse('chatcmpl-test');
    if (receipt.signatureKind !== 'provider_tee')
      throw new Error('Expected model receipt');
    expect(result.models[0].signingPublicKey).toBeUndefined();
    expect(receipt.attestations).toEqual([result.models[1], result.models[3]]);
    expect(receipt.attestation).toBe(result.models[1]);
  });

  test.each(
    [false, true].flatMap((e2ee) =>
      [false, true].map((stream) => ({ e2ee, stream })),
    ),
  )(
    'retains shared-signer reports for Chat (e2ee=$e2ee, stream=$stream)',
    async ({ e2ee, stream }) => {
      const gateway = createTestGateway({
        includeSecondModelAttestation: true,
        sharedModelSigner: true,
      });
      mockProviderSignatures(gateway);
      const deploymentPolicy = jest.fn();
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        e2ee,
        deploymentPolicy,
      });
      const preflight = await client.verify(model);
      expect(preflight.models).toHaveLength(2);
      expect(preflight.models[0].report.intelQuote).not.toBe(
        preflight.models[1].report.intelQuote,
      );
      expect(deploymentPolicy).toHaveBeenCalledTimes(2);

      const response = await client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({
          stream,
          messages: [{ role: 'user', content: 'hello model' }],
        }),
      );
      await response.text();
      const verified = await client.verifyResponse(
        stream
          ? 'chatcmpl-stream'
          : e2ee
            ? 'chatcmpl-test'
            : 'chatcmpl-plaintext',
      );
      expect(verified.signatureKind).toBe('provider_tee');
      if (verified.signatureKind !== 'provider_tee')
        throw new Error('Expected model receipt');
      expect(verified.attestations).toEqual(preflight.models);
      expect(verified.attestations[0]).toBe(preflight.models[0]);
      expect(verified.attestations[1]).toBe(preflight.models[1]);
      expect(verified.attestation).toBe(preflight.models[0]);
      expect(gateway.state.modelAttestationRequests).toBe(1);
    },
  );

  test.each([false, true])(
    'keeps Gateway receipts separate from model reports (stream=%s)',
    async (stream) => {
      const gateway = createTestGateway({
        includeSecondModelAttestation: true,
        sharedModelSigner: true,
      });
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(createSignatureFetch(gateway, 'gateway'));
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        e2ee: false,
      });
      const preflight = await client.verify(model);
      expect(preflight.models).toHaveLength(2);
      const response = await client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ stream, messages: [{ role: 'user', content: 'hello' }] }),
      );
      await response.text();
      const receipt = await client.verifyResponse(
        stream ? 'chatcmpl-stream' : 'chatcmpl-plaintext',
      );
      expect(receipt.signatureKind).toBe('gateway');
      expect(receipt.attestation).toBe(preflight.gateway);
      expect(receipt).not.toHaveProperty('attestations');
    },
  );

  test.each(['quote', 'policy'] as const)(
    'rejects a %s failure in the second shared-signer report before Chat',
    async (failure) => {
      const gateway = createTestGateway({
        includeSecondModelAttestation: true,
        sharedModelSigner: true,
      });
      mockProviderSignatures(gateway);
      const deploymentPolicy = jest.fn();
      if (failure === 'policy')
        deploymentPolicy
          .mockResolvedValueOnce(undefined)
          .mockRejectedValueOnce(new Error('second deployment rejected'));
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        modelVerification: {
          verifiers: {
            tdxQuote: async (quote) => {
              if (failure === 'quote' && quote.endsWith(':replica-2'))
                throw new Error('second quote rejected');
              return gateway.tdxQuoteVerifier(quote);
            },
          },
        },
        deploymentPolicy,
      });
      await expect(
        client.fetch(
          `${baseUrl}chat/completions`,
          chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
        ),
      ).rejects.toMatchObject({
        failure: {
          code:
            failure === 'quote'
              ? 'quote.verification_failed'
              : 'provenance.verification_failed',
        },
      });
      if (failure === 'policy')
        expect(deploymentPolicy).toHaveBeenCalledTimes(2);
      expect(gateway.state.completionRequests).toBe(0);
    },
  );

  test('keeps the request signer group after a later attestation refresh', async () => {
    const gateway = createTestGateway({
      includeSecondModelAttestation: true,
      sharedModelSigner: true,
    });
    mockProviderSignatures(gateway);
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      attestationCacheTimeToLiveMs: 0,
    });
    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello model' }],
    });
    const refreshed = await client.verify(model);
    const receipt = await client.verifyResponse(completion.id);
    if (receipt.signatureKind !== 'provider_tee')
      throw new Error('Expected model receipt');
    expect(receipt.attestations).toHaveLength(2);
    expect(receipt.attestations[0].report.nonce).not.toBe(
      refreshed.models[0].report.nonce,
    );
    expect(receipt.attestations[0].report.nonce).toBe(
      receipt.attestations[1].report.nonce,
    );
    expect(gateway.state.modelAttestationRequests).toBe(2);
  });

  test.each([false, true])(
    'rejects a provider signature from a different verified model candidate (e2ee=%s)',
    async (e2ee) => {
      const gateway = createTestGateway({
        includeSecondModelAttestation: true,
      });
      const signWithSelectedKey = gateway.createProviderSignature;
      const otherKey = keyPair(3);
      jest
        .spyOn(gateway, 'createProviderSignature')
        .mockImplementation((requestBody, responseBody) => {
          const signature = signWithSelectedKey(requestBody, responseBody);
          return {
            ...signature,
            signing_address: keyHex(otherKey.publicKey),
            signature: keyHex(
              nacl.sign.detached(
                Buffer.from(signature.text),
                otherKey.secretKey,
              ),
            ),
          };
        });
      mockProviderSignatures(gateway);
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        e2ee,
      });
      const completion = await client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello' }],
      });

      expect(
        gateway.state.completionRequestsSeen[0].headers.get('x-model-pub-key'),
      ).toBe(keyHex(keyPair(2).publicKey));
      const verification = client.verifyResponse(completion.id);
      await expect(verification).rejects.toMatchObject({
        failure: { code: 'signature.signer_mismatch' },
      });
      expect(retainedCapture(client, completion.id)).toBeUndefined();
      expect(client.verifyResponse(completion.id)).toBe(verification);
    },
  );

  test('decrypts a Chat Completions stream split across transport chunks', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const stream = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello model' }],
      stream: true,
    });
    let content = '';
    for await (const chunk of stream) {
      content += chunk.choices[0]?.delta.content ?? '';
    }

    expect(content).toBe('hello client');
  });

  test.each(['\n\n', '\r\n\r\n'])(
    'registers the first SSE event ending in %j before the next event arrives',
    async (separator) => {
      const gateway = createTestGateway({
        streamRecordSeparators: [separator],
      });
      const providerFetch = createSignatureFetch(gateway);
      let resumeStream: () => void = () => {};
      const nextEventReady = new Promise<void>((resolve) => {
        resumeStream = resolve;
      });
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(async (input, init) => {
          const response = await providerFetch(input, init);
          if (!isChatCompletionRequest(input)) return response;
          let chunks = 0;
          return new Response(
            response.body?.pipeThrough(
              new TransformStream<Uint8Array, Uint8Array>({
                async transform(chunk, controller) {
                  // The fixture splits its first event into two transport chunks.
                  if (chunks === 2) await nextEventReady;
                  chunks += 1;
                  controller.enqueue(chunk);
                },
              }),
            ),
            { headers: response.headers },
          );
        });
      const client = new InferenceClient(inferenceClientOptions(gateway));
      const stream = await client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello model' }],
        stream: true,
      });
      const iterator = stream[Symbol.asyncIterator]();
      const first = await iterator.next();
      expect(first.value?.choices[0]?.delta.content).toBe('hello ');
      const verification = expect(
        client.verifyResponse('chatcmpl-stream'),
      ).resolves.toMatchObject({
        id: 'chatcmpl-stream',
        signatureKind: 'provider_tee',
      });

      resumeStream();
      expect((await iterator.next()).value?.choices[0]?.delta.content).toBe(
        'client',
      );
      expect((await iterator.next()).done).toBe(true);
      await verification;
    },
  );

  test('finishing a cleared stream does not restore its expiry timer', async () => {
    const gateway = createTestGateway({ streamRecordSeparators: ['\n\n'] });
    let resumeStream!: () => void;
    const resume = new Promise<void>((resolve) => {
      resumeStream = resolve;
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const response = await gateway.fetch(input, init);
      if (!isChatCompletionRequest(input)) return response;
      let chunks = 0;
      return new Response(
        response.body?.pipeThrough(
          new TransformStream<Uint8Array, Uint8Array>({
            async transform(chunk, controller) {
              if (chunks++ === 2) await resume;
              controller.enqueue(chunk);
            },
          }),
        ),
        { headers: response.headers },
      );
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));
    jest.useFakeTimers({
      doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'],
    });
    const stream = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello' }],
      stream: true,
    });
    const iterator = stream[Symbol.asyncIterator]();
    const first = await iterator.next();
    expect(first.value?.choices[0]?.delta.content).toBe('hello ');
    client.clearResponseCache();
    resumeStream();
    expect((await iterator.next()).value?.choices[0]?.delta.content).toBe(
      'client',
    );
    expect((await iterator.next()).done).toBe(true);
    await expect(
      client.verifyResponse('chatcmpl-stream'),
    ).rejects.toMatchObject({
      failure: { code: 'api.completion_not_found' },
    });
    expect(jest.getTimerCount()).toBe(0);
  });

  test('returns a non-streaming completion with verifiable entity bodies', async () => {
    const gateway = createTestGateway();
    mockProviderSignatures(gateway);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello model' }],
    });

    expect(completion.choices[0]?.message.content).toBe('hello client');
    await expect(client.verifyResponse(completion.id)).resolves.toMatchObject({
      id: 'chatcmpl-test',
      signatureKind: 'provider_tee',
    });
  });

  test.each([
    {
      name: 'CRLF',
      separators: ['\r\n\r\n', '\r\n\r\n', '\r\n\r\n', '\r\n\r\n'],
    },
    { name: 'mixed', separators: ['\n\r\n', '\r\n\n', '\n\r', '\r\n\r'] },
  ])(
    'verifies multiline SSE with $name record separators after consuming the stream',
    async ({ separators }) => {
      const gateway = createTestGateway({
        streamRecordSeparators: separators,
      });
      mockProviderSignatures(gateway);
      const client = new InferenceClient(inferenceClientOptions(gateway));

      const stream = await client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello model' }],
        stream: true,
      });
      let content = '';
      for await (const chunk of stream) {
        content += chunk.choices[0]?.delta.content ?? '';
      }

      expect(content).toBe('hello client');
      await expect(
        client.verifyResponse('chatcmpl-stream'),
      ).resolves.toMatchObject({
        id: 'chatcmpl-stream',
        signatureKind: 'provider_tee',
      });
    },
  );

  test('supports a non-streaming OpenAI-compatible chat call', async () => {
    const gateway = createTestGateway({
      expectedRequestHeader: {
        name: 'authorization',
        value: 'Bearer browser-token',
      },
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient({
      baseUrl,
      headers: { authorization: 'Bearer browser-token' },
      e2ee: true,
      gatewayVerification: {
        verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
      },
      modelVerification: { verifiers: { tdxQuote: gateway.tdxQuoteVerifier } },
    });

    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello model' }],
    });

    expect(completion.choices[0]?.message.content).toBe('hello client');
    expect(gateway.state.decryptedRequestContent).toEqual(['hello model']);
  });

  test('accepts nullable and empty Chat response fields under E2EE', async () => {
    const gateway = createTestGateway({ includeNullableResponseFields: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: {
            content: 'hello client',
            audio: null,
            function_call: null,
            refusal: null,
            tool_calls: [],
          },
          logprobs: null,
        },
      ],
    });
  });

  test('decrypts rich response text and audio without rewriting other parts', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (!isChatCompletionRequest(input)) {
        return gateway.fetch(input, init);
      }
      const request = new Request(input, init);
      const clientPublicKey = request.headers.get('x-client-pub-key');
      if (clientPublicKey === null) {
        throw new Error('Expected an E2EE client key');
      }
      return jsonResponse({
        id: 'chatcmpl-rich-response',
        choices: [
          {
            message: {
              role: 'assistant',
              content: [
                {
                  type: 'text',
                  text: encryptE2eeText({
                    plaintext: 'The image shows a lighthouse.',
                    recipientPublicKey: clientPublicKey,
                  }),
                },
                {
                  type: 'image_url',
                  image_url: { url: 'https://example.test/result.png' },
                },
              ],
              audio: {
                format: 'wav',
                data: encryptE2eeText({
                  plaintext: 'audio bytes',
                  recipientPublicKey: clientPublicKey,
                }),
              },
              provider_metadata: { cache_hit: true },
            },
          },
        ],
      });
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'describe this' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: {
            content: [
              { type: 'text', text: 'The image shows a lighthouse.' },
              {
                type: 'image_url',
                image_url: { url: 'https://example.test/result.png' },
              },
            ],
            audio: { format: 'wav', data: 'audio bytes' },
            provider_metadata: { cache_hit: true },
          },
        },
      ],
    });
  });

  test('decrypts all-fields logprobs', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (!isChatCompletionRequest(input)) {
        return gateway.fetch(input, init);
      }
      const request = new Request(input, init);
      const clientPublicKey = request.headers.get('x-client-pub-key');
      if (clientPublicKey === null) {
        throw new Error('Expected an E2EE client key');
      }
      return jsonResponse({
        id: 'chatcmpl-logprobs',
        choices: [
          {
            message: {
              role: 'assistant',
              content: encryptE2eeText({
                plaintext: 'Hello',
                recipientPublicKey: clientPublicKey,
              }),
            },
            logprobs: {
              content: [
                {
                  token: encryptE2eeText({
                    plaintext: 'Hello',
                    recipientPublicKey: clientPublicKey,
                  }),
                  bytes: encryptE2eeText({
                    plaintext: JSON.stringify([72, 101, 108, 108, 111]),
                    recipientPublicKey: clientPublicKey,
                  }),
                  top_logprobs: [
                    {
                      token: encryptE2eeText({
                        plaintext: 'Hi',
                        recipientPublicKey: clientPublicKey,
                      }),
                      bytes: encryptE2eeText({
                        plaintext: JSON.stringify([72, 105]),
                        recipientPublicKey: clientPublicKey,
                      }),
                    },
                  ],
                },
              ],
              refusal: [
                {
                  token: encryptE2eeText({
                    plaintext: 'No',
                    recipientPublicKey: clientPublicKey,
                  }),
                  bytes: encryptE2eeText({
                    plaintext: JSON.stringify([78, 111]),
                    recipientPublicKey: clientPublicKey,
                  }),
                },
              ],
            },
          },
        ],
      });
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'Say hello.' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: { content: 'Hello' },
          logprobs: {
            content: [
              {
                token: 'Hello',
                bytes: [72, 101, 108, 108, 111],
                top_logprobs: [{ token: 'Hi', bytes: [72, 105] }],
              },
            ],
            refusal: [{ token: 'No', bytes: [78, 111] }],
          },
        },
      ],
    });
  });

  test('uses all-fields E2EE for standard function tools', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [{ role: 'user', content: 'check the weather' }],
        tools: [
          {
            type: 'function',
            function: {
              name: 'weather',
              description: 'Look up the current weather.',
              parameters: {
                type: 'object',
                properties: { city: { type: 'string' } },
              },
            },
          },
        ],
      }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: {
            tool_calls: [
              {
                function: { name: 'weather', arguments: '{"city":"Shanghai"}' },
              },
            ],
          },
        },
      ],
    });
    expect(gateway.state.decryptedTool).toEqual({
      name: 'weather',
      description: 'Look up the current weather.',
      parameters: JSON.stringify({
        type: 'object',
        properties: { city: { type: 'string' } },
      }),
    });
    expect(
      gateway.state.completionRequestsSeen[0].headers.get(
        'x-encrypt-all-fields',
      ),
    ).toBe('true');
  });

  test('preserves response fields the SDK does not transform', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (!isChatCompletionRequest(input)) {
        return gateway.fetch(input, init);
      }
      return jsonResponse({
        id: 'chatcmpl-tool-result',
        choices: [
          {
            message: {
              role: 'assistant',
              content: null,
              audio: { format: 'mp3', data: null },
              tool_calls: [
                {
                  type: 'function',
                  function: { name: null, arguments: null },
                },
              ],
              function_call: { name: null, arguments: null },
            },
            logprobs: { content: [] },
          },
        ],
      });
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [{ role: 'user', content: 'check the weather' }],
        tools: [
          {
            type: 'function',
            function: { name: 'weather', parameters: { type: 'object' } },
          },
        ],
      }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: {
            audio: { format: 'mp3', data: null },
            tool_calls: [{ function: { name: null, arguments: null } }],
            function_call: { name: null, arguments: null },
          },
          logprobs: { content: [] },
        },
      ],
    });
  });

  test('encrypts a tool continuation and decrypts all-fields response values', async () => {
    const gateway = createTestGateway({
      encryptedRefusal: 'I cannot provide that information.',
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [
          { role: 'user', content: 'What is the weather in Shanghai?' },
          {
            role: 'assistant',
            content: null,
            tool_calls: [
              {
                id: 'call_1',
                type: 'function',
                function: {
                  name: 'weather',
                  arguments: '{"city":"Shanghai"}',
                },
              },
            ],
          },
          {
            role: 'tool',
            tool_call_id: 'call_1',
            content: '22 C and clear.',
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: 'weather',
              parameters: { type: 'object' },
            },
          },
        ],
        tool_choice: { type: 'function', function: { name: 'weather' } },
      }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: {
            refusal: 'I cannot provide that information.',
            tool_calls: [
              {
                function: { name: 'weather', arguments: '{"city":"Shanghai"}' },
              },
            ],
          },
        },
      ],
    });
    expect(gateway.state.decryptedRequestContent).toEqual([
      'What is the weather in Shanghai?',
      '22 C and clear.',
    ]);
    expect(gateway.state.decryptedInputToolCalls).toEqual([
      { name: 'weather', arguments: '{"city":"Shanghai"}' },
    ]);
    expect(gateway.state.decryptedNamedToolChoice).toBe('weather');
  });

  test('decrypts standard function tool calls in a Chat Completions stream', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const stream = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'check the weather' }],
      stream: true,
      tools: [
        {
          type: 'function',
          function: {
            name: 'weather',
            description: 'Look up the current weather.',
            parameters: { type: 'object' },
          },
        },
      ],
    });
    const toolCalls: Array<{ name?: string; arguments?: string }> = [];
    for await (const chunk of stream) {
      for (const toolCall of chunk.choices[0]?.delta.tool_calls ?? []) {
        toolCalls.push({
          name: toolCall.function?.name,
          arguments: toolCall.function?.arguments,
        });
      }
    }

    expect(toolCalls).toEqual([
      { name: 'weather', arguments: '{"city":"Shanghai"}' },
    ]);
    expect(
      gateway.state.completionRequestsSeen[0].headers.get(
        'x-encrypt-all-fields',
      ),
    ).toBe('true');
  });

  test('supports an encrypted web_context_search stream', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [{ role: 'user', content: 'Search for NEAR AI.' }],
        stream: true,
        tools: [{ type: 'web_context_search' }],
      }),
    );
    const stream = await response.text();

    expect(stream).toContain('"name":"web_context_search"');
    expect(stream).toContain('"arguments":"{\\"query\\":\\"NEAR AI\\"}"');
    expect(stream).toContain('"output":"NEAR AI search result"');
    expect(
      gateway.state.completionRequestsSeen[0].headers.get(
        'x-encrypt-all-fields',
      ),
    ).toBe('true');
    expect(gateway.state.completionRequestsSeen[0].body.tools).toEqual([
      { type: 'web_context_search' },
    ]);
  });

  test('leaves web_context_search request acceptance to the Gateway', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [{ role: 'user', content: 'Search for NEAR AI.' }],
        tools: [{ type: 'web_context_search' }],
      }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [{ message: { content: 'hello client' } }],
    });
    expect(gateway.state.completionRequests).toBe(1);
  });

  test('fails closed when an encrypted Chat response is tampered with', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const response = await gateway.fetch(input, init);
      if (!isChatCompletionRequest(input)) {
        return response;
      }
      return jsonResponse({
        id: 'chatcmpl-tampered',
        choices: [
          {
            message: {
              role: 'assistant',
              content: 'not-a-valid-ciphertext',
            },
          },
        ],
      });
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await expect(
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      ),
    ).rejects.toMatchObject({
      failure: {
        code: 'e2ee.decryption_failed',
        details: { field: 'choices[0].message.content' },
      },
    });
    expect(gateway.state.completionRequests).toBe(1);
  });

  test('returns non-success Chat responses without decrypting them', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (!isChatCompletionRequest(input)) {
        return gateway.fetch(input, init);
      }
      return new Response(JSON.stringify({ error: { message: 'try later' } }), {
        status: 503,
        headers: { 'content-type': 'application/json' },
      });
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: { message: 'try later' },
    });
  });

  test.each([undefined, false])(
    'keeps verification and model routing with e2ee=%s',
    async (e2ee) => {
      const gateway = createTestGateway();
      mockProviderSignatures(gateway);
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        e2ee,
      });
      const richContent = [{ type: 'text', text: 'plain Chat payload' }];

      const response = await client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: richContent }] }),
      );

      const completion = await response.json();
      expect(completion).toMatchObject({
        choices: [{ message: { content: 'plaintext response' } }],
      });
      await expect(client.verifyResponse(completion.id)).resolves.toMatchObject(
        {
          signatureKind: 'provider_tee',
          signature: { signer: { signingAlgo: 'ed25519' } },
        },
      );
      expect(gateway.state).toMatchObject({
        gatewayAttestationRequests: 1,
        modelAttestationRequests: 1,
        completionRequests: 1,
      });
      const request = gateway.state.completionRequestsSeen[0];
      expect(request.body.messages).toEqual([
        { role: 'user', content: richContent },
      ]);
      expect(request.headers.get('x-signing-algo')).toBeNull();
      expect(request.headers.get('x-client-pub-key')).toBeNull();
      expect(request.headers.get('x-model-pub-key')).toBe(
        keyHex(keyPair(2).publicKey),
      );
    },
  );

  test.each(['verifier', 'policy'])(
    'does not send a completion when the model deployment %s rejects it',
    async (rejectedHook) => {
      const gateway = createTestGateway();
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      const deployment = jest.fn(async () => {
        if (rejectedHook === 'verifier')
          throw new Error('deployment is not approved');
      });
      const deploymentPolicy = jest.fn(async () => {
        if (rejectedHook === 'policy')
          throw new Error('deployment is not approved');
      });
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        modelVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier, deployment },
        },
        deploymentPolicy,
      });

      await expect(client.verify(model)).rejects.toMatchObject({
        failure: { code: 'provenance.verification_failed' },
      });
      await expect(
        client.fetch(
          `${baseUrl}chat/completions`,
          chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
        ),
      ).rejects.toMatchObject({
        failure: { code: 'provenance.verification_failed' },
      });
      expect(deployment).toHaveBeenCalledTimes(2);
      expect(deploymentPolicy).toHaveBeenCalledTimes(
        rejectedHook === 'verifier' ? 0 : 2,
      );
      expect(gateway.state.completionRequests).toBe(0);
    },
  );

  test('does not send a completion when model verification fails', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      modelVerification: {
        verifiers: {
          tdxQuote: () => {
            throw new Error('model quote rejected');
          },
        },
      },
    });

    await expect(
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      ),
    ).rejects.toMatchObject({
      failure: { code: 'quote.verification_failed' },
    });
    expect(gateway.state.completionRequests).toBe(0);
  });

  test.each(['http', 'empty'] as const)(
    'does not fall back to Gateway-only when NEAR evidence is %s',
    async (failure) => {
      const gateway = createTestGateway();
      jest.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const request = new Request(input, init);
        const url = new URL(request.url);
        if (
          url.pathname === '/v1/attestation/report' &&
          url.searchParams.has('model')
        ) {
          expect(url.searchParams.get('provider')).toBe('near');
          return Promise.resolve(
            failure === 'http'
              ? new Response('', { status: 503 })
              : jsonResponse({ model_attestations: [] }),
          );
        }
        return gateway.fetch(request);
      });
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        e2ee: false,
      });

      await expect(
        client.fetch(
          `${baseUrl}chat/completions`,
          chatRequest({ messages: [] }),
        ),
      ).rejects.toMatchObject({
        failure: {
          code:
            failure === 'http'
              ? 'api.http_status'
              : 'policy.model_attestation_required',
        },
      });
      expect(gateway.state.completionRequests).toBe(0);
    },
  );

  test('encrypts rich content and forwards other Chat fields to the Gateway', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));
    const richContent = [
      { type: 'text', text: 'describe this image' },
      {
        type: 'image_url',
        image_url: { url: 'https://example.test/image.png' },
      },
    ];

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [
          {
            role: 'user',
            content: richContent,
            provider_message_option: { detail: 'high' },
          },
        ],
        response_format: { type: 'json_object' },
        provider_request_option: { priority: 'normal' },
        tools: [{ type: 'provider_extension', setting: 'enabled' }],
      }),
    );

    expect(JSON.parse(gateway.state.decryptedRequestContent[0] ?? '')).toEqual(
      richContent,
    );
    expect(gateway.state.completionRequestsSeen[0]?.body).toMatchObject({
      response_format: { type: 'json_object' },
      provider_request_option: { priority: 'normal' },
      tools: [{ type: 'provider_extension', setting: 'enabled' }],
      messages: [
        {
          provider_message_option: { detail: 'high' },
        },
      ],
    });
    expect(
      gateway.state.completionRequestsSeen[0]?.headers.get(
        'x-encrypt-all-fields',
      ),
    ).toBe('true');
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 1,
    });
  });

  test('rejects unsupported paths before it fetches attestation evidence', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await expect(
      client.fetch(
        `${baseUrl}responses/resp_fixture`,
        chatRequest({ input: 'hello model' }),
      ),
    ).rejects.toMatchObject({
      failure: { code: 'api.invalid_input', details: { field: 'request' } },
    });
    expect(gateway.state.gatewayAttestationRequests).toBe(0);
    expect(gateway.state.modelAttestationRequests).toBe(0);
  });

  describe.each([
    { providerType: 'external', attestationSupported: false },
    { providerType: 'chutes', attestationSupported: true },
    { providerType: 'vllm', attestationSupported: false },
  ])('Gateway-only $providerType models', (metadata) => {
    test.each([
      { entrypoint: 'fetch', stream: false, configuration: 'empty' },
      { entrypoint: 'fetch', stream: true, configuration: 'backends' },
      { entrypoint: 'chat', stream: false, configuration: 'backends' },
      { entrypoint: 'chat', stream: true, configuration: 'empty' },
    ])(
      'verifies plaintext with $entrypoint (stream=$stream, model verification=$configuration)',
      async ({ entrypoint, stream, configuration }) => {
        const gateway = createTestGateway(metadata);
        const tdxQuote = jest.fn(gateway.tdxQuoteVerifier);
        const gpuEvidence = jest.fn();
        jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation(createSignatureFetch(gateway, 'gateway'));
        const client = new InferenceClient({
          ...inferenceClientOptions(gateway),
          e2ee: false,
          modelVerification:
            configuration === 'empty'
              ? {}
              : { verifiers: { tdxQuote, gpuEvidence } },
          headers: {
            [aggregatorHeader.name]: aggregatorHeader.value,
            'x-model-pub-key': 'stale-default-key',
          },
        });
        const headers = {
          'content-type': 'application/json',
          'x-model-pub-key': 'stale-request-key',
          'x-signing-algo': 'ed25519',
          'x-client-pub-key': 'stale-client-key',
          'x-encryption-version': '2',
          'x-encrypt-all-fields': 'true',
        };
        const body = {
          model,
          messages: [{ role: 'user' as const, content: 'UTF-8: A é € 🌍' }],
        };
        let completionId: string;
        if (entrypoint === 'fetch') {
          const response = await client.fetch(`${baseUrl}chat/completions`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ ...body, stream }, null, 2),
          });
          if (stream) {
            expect(await response.text()).toContain('plaintext response');
            completionId = 'chatcmpl-stream';
          } else {
            const completion = await response.json();
            expect(completion.choices[0].message.content).toBe(
              'plaintext response',
            );
            completionId = completion.id;
          }
        } else if (stream) {
          const completion = await client.chat.completions.create(
            { ...body, stream: true },
            { headers },
          );
          completionId = '';
          let content = '';
          for await (const event of completion) {
            completionId = event.id;
            content += event.choices[0]?.delta.content ?? '';
          }
          expect(content).toBe('plaintext response');
        } else {
          const completion = await client.chat.completions.create(body, {
            headers,
          });
          expect(completion.choices[0].message.content).toBe(
            'plaintext response',
          );
          completionId = completion.id;
        }
        await expect(
          client.verifyResponse(completionId),
        ).resolves.toMatchObject({
          id: completionId,
          signatureKind: 'gateway',
          attestation: {
            signer: { signingAddress: keyHex(keyPair(1).publicKey) },
          },
        });
        expect(gateway.state).toMatchObject({
          gatewayAttestationRequests: 1,
          metadataModels: [model],
          modelAttestationRequests: 0,
          completionRequests: 1,
        });
        const sent = gateway.state.completionRequestsSeen[0];
        expect(sent.body.messages).toEqual([
          { role: 'user', content: 'UTF-8: A é € 🌍' },
        ]);
        for (const name of [
          'x-model-pub-key',
          'x-signing-algo',
          'x-client-pub-key',
          'x-encryption-version',
          'x-encrypt-all-fields',
        ])
          expect(sent.headers.has(name)).toBe(false);
        expect(sent.headers.get('x-no-aliasing')).toBe('true');
        expect(tdxQuote).not.toHaveBeenCalled();
        expect(gpuEvidence).not.toHaveBeenCalled();
      },
    );

    test('uses pinned metadata and Gateway OHTTP for JSON and SSE without model evidence', async () => {
      const gateway = createTestGateway(metadata);
      const endpoint = await createOhttpEndpoint({
        fetch: createSignatureFetch(gateway, 'gateway'),
        signingKey: keyPair(1),
      });
      mockNodeGatewayAttestation({
        gateway: { ...gateway, fetch: endpoint.fetch },
      });
      const pinnedFetch = jest.fn(endpoint.fetch);
      const rawFetch = jest.spyOn(globalThis, 'fetch');
      const client = new TestNodeInferenceClient(
        {
          ...inferenceClientOptions(gateway),
          e2ee: false,
          ohttp: true,
          signingAlgo: 'ed25519',
        },
        pinnedFetch,
      );

      const completion = await client.chat.completions.create({
        model,
        messages: [],
      });
      await expect(client.verifyResponse(completion.id)).resolves.toMatchObject(
        {
          signatureKind: 'gateway',
        },
      );
      const stream = await client.chat.completions.create({
        model,
        messages: [],
        stream: true,
      });
      let id = '';
      let content = '';
      for await (const event of stream) {
        id = event.id;
        content += event.choices[0]?.delta.content ?? '';
      }
      expect(content).toBe('plaintext response');
      await expect(client.verifyResponse(id)).resolves.toMatchObject({
        signatureKind: 'gateway',
      });
      expect(gateway.state).toMatchObject({
        gatewayAttestationRequests: 1,
        metadataModels: [model],
        modelAttestationRequests: 0,
      });
      expect(client.pinnedSpkiFingerprints).toEqual([tlsFingerprint]);
      expect(rawFetch).not.toHaveBeenCalled();
      expect(
        pinnedFetch.mock.calls.map(
          ([request]) => new URL((request as Request).url).pathname,
        ),
      ).toEqual([
        `/v1/model/${model}`,
        '/ohttp',
        `/v1/signature/${completion.id}`,
        '/ohttp',
        `/v1/signature/${id}`,
      ]);
    });

    test.each(['tampered', 'provider_tee'] as const)(
      'rejects a %s receipt',
      async (receipt) => {
        const gateway = createTestGateway(metadata);
        const signatureFetch = createSignatureFetch(
          gateway,
          receipt === 'provider_tee' ? 'provider_tee' : 'gateway',
        );
        jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation(async (input, init) => {
            const request = new Request(input, init);
            const response = await signatureFetch(request);
            if (
              receipt === 'tampered' &&
              new URL(request.url).pathname.startsWith('/v1/signature/')
            ) {
              return jsonResponse({
                ...(await response.json()),
                signature: '00'.repeat(64),
              });
            }
            return response;
          });
        const client = new InferenceClient({
          ...inferenceClientOptions(gateway),
          e2ee: false,
        });
        const completion = await client.chat.completions.create({
          model,
          messages: [],
        });

        await expect(
          client.verifyResponse(completion.id),
        ).rejects.toMatchObject({
          failure: {
            code:
              receipt === 'tampered'
                ? 'signature.invalid'
                : 'signature.kind_mismatch',
          },
        });
      },
    );

    test.each([
      { name: 'field encryption', options: { e2ee: true } },
      {
        name: 'deployment policy',
        options: { deploymentPolicy: () => undefined },
      },
      {
        name: 'model evidence policy',
        options: { modelVerification: { policy: {} } },
      },
      {
        name: 'deployment verifier',
        options: {
          modelVerification: { verifiers: { deployment: () => undefined } },
        },
      },
    ])('rejects explicit $name requirements', async ({ options }) => {
      const gateway = createTestGateway(metadata);
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        e2ee: false,
        ...options,
      });

      await expect(
        client.fetch(
          `${baseUrl}chat/completions`,
          chatRequest({ messages: [] }),
        ),
      ).rejects.toMatchObject({
        failure: { code: 'policy.model_attestation_required' },
      });
      expect(gateway.state).toMatchObject({
        metadataModels: [model],
        modelAttestationRequests: 0,
        completionRequests: 0,
      });
    });

    test.each(['http', 'schema'] as const)(
      'does not fall back when catalog %s fails',
      async (failure) => {
        const gateway = createTestGateway(metadata);
        jest
          .spyOn(globalThis, 'fetch')
          .mockImplementation(async (input, init) => {
            const request = new Request(input, init);
            if (new URL(request.url).pathname.startsWith('/v1/model/')) {
              return failure === 'http'
                ? new Response('', { status: 503 })
                : jsonResponse({ metadata: {} });
            }
            return gateway.fetch(request);
          });
        const client = new InferenceClient({
          ...inferenceClientOptions(gateway),
          e2ee: false,
        });

        await expect(
          client.fetch(
            `${baseUrl}chat/completions`,
            chatRequest({ messages: [] }),
          ),
        ).rejects.toMatchObject({
          failure: {
            code:
              failure === 'http' ? 'api.http_status' : 'api.invalid_response',
          },
        });
        expect(gateway.state.gatewayAttestationRequests).toBe(1);
        expect(gateway.state.modelAttestationRequests).toBe(0);
        expect(gateway.state.completionRequests).toBe(0);
      },
    );
  });

  describe.each(['browser', 'Node'] as const)(
    '%s Gateway authentication boundary',
    (runtime) => {
      test('does not send credentials after rejected Gateway verification and can retry', async () => {
        const gateway = createTestGateway();
        const providerFetch = createSignatureFetch(gateway);
        jest.spyOn(globalThis, 'fetch').mockImplementation(providerFetch);
        const failure = new VerificationError({ code: 'policy.debug_enabled' });
        let rejectGateway = true;
        const options: InferenceClientOptions = {
          ...inferenceClientOptions(gateway),
          apiKey: 'configured-key',
          gatewayVerification: {
            verifiers: {
              tdxQuote: async (quote) => {
                await Promise.resolve();
                if (rejectGateway) throw failure;
                return gateway.tdxQuoteVerifier(quote);
              },
            },
          },
        };
        if (runtime === 'Node') mockNodeGatewayAttestation({ gateway });
        const client =
          runtime === 'Node'
            ? new TestNodeInferenceClient(options, providerFetch)
            : new InferenceClient(options);
        for (let attempt = 0; attempt < 2; attempt += 1) {
          await expect(client.verify(model)).rejects.toBe(failure);
          expect(gateway.state.metadataModels).toEqual([]);
          expect(gateway.state.modelAttestationRequests).toBe(0);
          expect(gateway.state.completionRequests).toBe(0);
        }
        rejectGateway = false;
        await client.verify(model);
        const completion = await client.chat.completions.create({
          model,
          messages: [{ role: 'user', content: 'hello after retry' }],
        });
        await client.verifyResponse(completion.id);
        expect(gateway.state.gatewayAttestationRequests).toBe(3);
        expect(gateway.state.completionRequests).toBe(1);
      });
    },
  );

  describe('Node inference client', () => {
    test('waits for Gateway verification before sending model credentials and Chat', async () => {
      const gateway = createTestGateway();
      const unpinnedFetch = jest
        .spyOn(globalThis, 'fetch')
        .mockRejectedValue(new Error('Unexpected unpinned Gateway request'));
      const capturedPeerSpkiFingerprints = mockNodeGatewayAttestation({
        gateway,
      });
      let releaseGatewayVerification: () => void = () => {};
      const gatewayVerificationPending = new Promise<void>((resolve) => {
        releaseGatewayVerification = resolve;
      });
      let notifyGatewayStarted: () => void = () => {};
      const gatewayStarted = new Promise<void>((resolve) => {
        notifyGatewayStarted = resolve;
      });
      const client = new TestNodeInferenceClient(
        {
          ...inferenceClientOptions(gateway),
          gatewayVerification: {
            verifiers: {
              tdxQuote: async (quote) => {
                notifyGatewayStarted();
                await gatewayVerificationPending;
                return gateway.tdxQuoteVerifier(quote);
              },
            },
          },
          modelVerification: {
            verifiers: {
              tdxQuote: gateway.tdxQuoteVerifier,
            },
          },
        },
        gateway.fetch,
      );

      const preverification = client.verify(model);
      const completion = client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello model' }],
      });
      await gatewayStarted;
      expect(gateway.state.metadataModels).toEqual([]);
      expect(gateway.state.modelAttestationRequests).toBe(0);
      expect(gateway.state.completionRequests).toBe(0);
      expect(client.pinnedSpkiFingerprints).toEqual([]);

      releaseGatewayVerification();
      const result = await preverification;
      expect(result.gateway.tlsBinding).toEqual({
        kind: 'attested',
        spkiFingerprint: tlsFingerprint,
      });
      await completion;

      expect(capturedPeerSpkiFingerprints).toEqual([true]);
      expect(client.pinnedSpkiFingerprints).toEqual([tlsFingerprint]);
      expect(gateway.state.gatewayAttestationIncludeSpkiFingerprints).toEqual([
        true,
      ]);
      expect(gateway.state.gatewayAttestationRequests).toBe(1);
      expect(gateway.state.modelAttestationRequests).toBe(1);
      expect(gateway.state.completionRequests).toBe(1);
      expect(unpinnedFetch).not.toHaveBeenCalled();
    });

    test('uses the pinned transport for model evidence, completion, and its response signature', async () => {
      const gateway = createTestGateway();
      const providerFetch = createSignatureFetch(gateway);
      const pinnedPaths: string[] = [];
      const pinnedFetch: typeof globalThis.fetch = async (input, init) => {
        const url =
          input instanceof Request ? input.url : new URL(input).toString();
        pinnedPaths.push(new URL(url).pathname);
        return providerFetch(input, init);
      };
      jest.spyOn(globalThis, 'fetch').mockImplementation(async () => {
        throw new Error('Unexpected unpinned Gateway request');
      });
      mockNodeGatewayAttestation({ gateway });
      const client = new TestNodeInferenceClient(
        inferenceClientOptions(gateway),
        pinnedFetch,
      );

      const response = await client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      );
      await response.text();
      await client.verifyResponse('chatcmpl-test');

      expect(client.pinnedSpkiFingerprints).toEqual([tlsFingerprint]);
      expect(pinnedPaths).toEqual([
        `/v1/model/${model}`,
        '/v1/attestation/report',
        '/v1/chat/completions',
        '/v1/signature/chatcmpl-test',
      ]);
    });

    test('can disable Gateway TLS binding for an aggregator or proxy', async () => {
      const gateway = createTestGateway();
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      const capturedPeerSpkiFingerprints = mockNodeGatewayAttestation({
        gateway,
      });
      const client = new NodeInferenceClient({
        ...inferenceClientOptions(gateway),
        gatewayVerification: {
          includeSpkiFingerprint: false,
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
      });

      await client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      );

      expect(capturedPeerSpkiFingerprints).toEqual([false]);
      expect(gateway.state.gatewayAttestationIncludeSpkiFingerprints).toEqual([
        false,
      ]);
      expect(gateway.state.completionRequests).toBe(1);
    });

    test('blocks the completion when the Gateway TLS peer does not match', async () => {
      const gateway = createTestGateway();
      const unpinnedFetch = jest
        .spyOn(globalThis, 'fetch')
        .mockRejectedValue(new Error('Unexpected unpinned Gateway request'));
      const peerSpkiFingerprint = '44'.repeat(32);
      mockNodeGatewayAttestation({
        gateway,
        peerSpkiFingerprint,
      });
      const client = new TestNodeInferenceClient(
        inferenceClientOptions(gateway),
        gateway.fetch,
      );

      await expect(
        client.fetch(
          `${baseUrl}chat/completions`,
          chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
        ),
      ).rejects.toMatchObject({
        failure: { code: 'binding.spki_fingerprint_mismatch' },
      });
      // A rejected peer is never used for authenticated evidence requests.
      expect(client.pinnedSpkiFingerprints).toEqual([]);
      expect(gateway.state.metadataModels).toEqual([]);
      expect(gateway.state.modelAttestationRequests).toBe(0);
      expect(gateway.state.completionRequests).toBe(0);
      expect(unpinnedFetch).not.toHaveBeenCalled();
    });

    test('requires an observed TLS fingerprint before fetching model evidence', async () => {
      const gateway = createTestGateway();
      const prototype =
        NodeAttestationClient.prototype as unknown as NodeAttestationClientPrototype;
      jest
        .spyOn(prototype, 'requestGatewayAttestation')
        .mockImplementation(async (request) => ({
          response: await gateway.fetch(request),
        }));
      const client = new TestNodeInferenceClient(
        inferenceClientOptions(gateway),
        gateway.fetch,
      );

      await expect(client.verify(model)).rejects.toMatchObject({
        failure: { code: 'binding.spki_fingerprint_required' },
      });
      expect(client.pinnedSpkiFingerprints).toEqual([]);
      expect(gateway.state.metadataModels).toEqual([]);
      expect(gateway.state.modelAttestationRequests).toBe(0);
      expect(gateway.state.completionRequests).toBe(0);
    });
  });
});

describe('native inference retry policy', () => {
  afterEach(() => jest.restoreAllMocks());
  test.each(['chat/completions', 'responses', 'messages'])(
    'does not replay a failed %s request',
    async (endpoint) => {
      const gateway = createTestGateway();
      let inferenceRequests = 0;
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(async (input, init) => {
          const request = new Request(input, init);
          if (new URL(request.url).pathname === `/v1/${endpoint}`) {
            inferenceRequests++;
            return new Response('{"error":{"message":"fixture failure"}}', {
              status: 500,
              headers: { 'content-type': 'application/json' },
            });
          }
          return gateway.fetch(request);
        });
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        e2ee: false,
      });
      const call =
        endpoint === 'messages'
          ? client.messages.create({
              model,
              messages: [{ role: 'user', content: 'Hello' }],
              max_tokens: 128,
            })
          : endpoint === 'responses'
            ? client.responses.create({ model, input: 'Hello' })
            : client.chat.completions.create({
                model,
                messages: [{ role: 'user', content: 'Hello' }],
              });
      await expect(call).rejects.toMatchObject({ status: 500 });
      expect(inferenceRequests).toBe(1);
    },
  );
});

describe('ECDSA Chat', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test.each(
    [false, true].flatMap((e2ee) =>
      [false, true].flatMap((stream) =>
        (['provider_tee', 'gateway'] as const).map((signatureKind) => ({
          e2ee,
          stream,
          signatureKind,
        })),
      ),
    ),
  )(
    'verifies ECDSA Chat and its original evidence group (e2ee=$e2ee, stream=$stream, kind=$signatureKind)',
    async ({ e2ee, stream, signatureKind }) => {
      const gateway = createEcdsaGateway({
        signatureKind,
        modelReportCount: 2,
      });
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      const client = new InferenceClient({
        baseUrl,
        headers: { authorization: 'Bearer test-token' },
        signingAlgo: 'ecdsa',
        e2ee,
        gatewayVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
        modelVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
      });
      const preflight = await client.verify(model);
      expect(preflight.models).toHaveLength(2);
      const response = await client.fetch(`${baseUrl}chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          model,
          stream,
          messages: [{ role: 'user', content: 'private ECDSA request' }],
        }),
      });
      const plaintext = await response.text();
      if (stream) {
        expect(plaintext).toContain('"content":"private ECDSA response"');
        expect(plaintext).toContain('data: [DONE]');
      } else {
        expect(JSON.parse(plaintext)).toMatchObject({
          choices: [{ message: { content: 'private ECDSA response' } }],
        });
      }
      const receipt = await client.verifyResponse('chatcmpl-ecdsa');
      expect(receipt.signatureKind).toBe(signatureKind);
      if (receipt.signatureKind === 'provider_tee') {
        expect(receipt.attestations).toEqual(preflight.models);
        expect(receipt.attestation).toBe(preflight.models[0]);
      } else {
        expect(receipt.attestation).toBe(preflight.gateway);
        expect(receipt).not.toHaveProperty('attestations');
      }
      expect(gateway.state.decryptedPrompts).toEqual(['private ECDSA request']);
      expect(gateway.state.attestationAlgorithms).toEqual(['ecdsa', 'ecdsa']);
      expect(gateway.state.signatureAlgorithms).toEqual(['ecdsa']);
      expect(gateway.state.completionHeaders).toHaveLength(1);
      const headers = gateway.state.completionHeaders[0];
      expect(headers.get('x-model-pub-key')).toBe(modelPublicKey);
      expect(headers.get('x-encryption-version')).toBe(e2ee ? '3' : null);
      if (e2ee) {
        expect(headers.get('x-signing-algo')).toBe('ecdsa');
        expect(headers.get('x-client-pub-key')).toHaveLength(128);
        expect(headers.get('x-encrypt-all-fields')).toBe('true');
      } else {
        expect(headers.has('x-signing-algo')).toBe(false);
        expect(headers.has('x-client-pub-key')).toBe(false);
        expect(headers.has('x-encrypt-all-fields')).toBe(false);
      }
    },
  );
});
