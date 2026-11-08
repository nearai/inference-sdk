import { Buffer } from 'node:buffer';
import { box, choice, noul, score, TypeSafeClient } from '@typesafe-ai/sdk';
import nacl from 'tweetnacl';
import {
  InferenceClient,
  type SystemOneRequest,
  VerificationError,
} from '../src';
import { createEcdsaGateway, modelPublicKey } from './ecdsa-gateway-fixtures';
import { tlsFingerprint } from './fixtures';
import {
  aggregatorHeader,
  baseUrl,
  createSignatureFetch,
  createTestGateway,
  fixtureId,
  inferenceClientOptions,
  jsonResponse,
  keyHex,
  keyPair,
  mockNodeGatewayAttestation,
  model,
  retainedCapture,
  TestNodeInferenceClient,
} from './inference-client-fixtures';

describe('System One decisions', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  const decisionRequest = {
    model,
    state: { message: 'Charged twice — please help 🌎' },
    questions: {
      billing: {
        type: 'noul' as const,
        instructions: 'Is this about billing?',
      },
      team: {
        type: 'choice' as const,
        instructions: { task: 'Choose the team that should handle this.' },
        criteria: { billing: null, support: 'Other issues' },
      },
      urgency: {
        type: 'score' as const,
        instructions: ['Rate the urgency.', { context: 'Customer support' }],
        criteria: ['Low', 'High'],
      },
    },
  };
  const decisionResponse = {
    id: 'decision-receipt',
    model,
    answers: {
      billing: { type: 'noul', noul: 0.98 },
      team: {
        type: 'choice',
        choice: 'billing',
        confidence: 0.9,
        probabilities: { billing: 0.9, support: 0.1 },
      },
      urgency: {
        type: 'score',
        score: 0.6,
        confidence: 0.7,
        probabilities: { '0': 0.4, '1': 0.6 },
        legend: { '0': 'Low', '1': 'High' },
      },
    },
    usage: { input_tokens: 12, output_tokens: 3 },
    future_field: 'preserved',
  };

  type DecisionGatewayParams = {
    tee?: boolean;
    secondSigner?: boolean;
    tamper?: boolean;
    missingId?: boolean;
    encoding?: string;
    decisionId?: string;
    malformed?: boolean;
    status?: number;
    failSignatureOnce?: boolean;
    unavailableSignatureOnce?: boolean;
    omitBodyId?: boolean;
    unknownSigner?: boolean;
    includeModelPublicKey?: boolean;
    response?: Record<string, unknown>;
  };

  function decisionGateway({
    tee = false,
    secondSigner = false,
    tamper = false,
    missingId = false,
    encoding,
    decisionId = 'decision-receipt',
    malformed = false,
    status = 200,
    failSignatureOnce = false,
    unavailableSignatureOnce = false,
    omitBodyId = false,
    unknownSigner = false,
    includeModelPublicKey = true,
    response = decisionResponse,
  }: DecisionGatewayParams = {}) {
    const gateway = createTestGateway({
      providerType: tee ? 'vllm' : 'external',
      attestationSupported: tee,
      includeModelPublicKey,
      includeSecondModelAttestation: secondSigner,
    });
    const chatFetch = createSignatureFetch(gateway);
    const requests: Request[] = [];
    const signaturePaths: string[] = [];
    const receipts = new Map<string, Record<string, string>>();
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === '/v1/systemone') {
        gateway.expectRequestHeader(request);
        requests.push(request.clone());
        const id = fixtureId(decisionId, requests.length);
        const requestBytes = new Uint8Array(await request.arrayBuffer());
        const responseText = `${JSON.stringify({ ...response, ...(omitBodyId ? { id: undefined } : {}) }, null, 2)}\n`;
        const responseBytes = new TextEncoder().encode(responseText);
        let receipt = tee
          ? gateway.createProviderSignature(requestBytes, responseBytes)
          : gateway.createGatewaySignature(requestBytes, responseBytes);
        if (secondSigner || unknownSigner) {
          receipt = {
            ...receipt,
            signing_address: keyHex(keyPair(3).publicKey),
            signature: keyHex(
              nacl.sign.detached(
                Buffer.from(receipt.text),
                keyPair(3).secretKey,
              ),
            ),
          };
        }
        receipts.set(id, receipt);
        return new Response(
          malformed
            ? '{}'
            : tamper
              ? responseText.replace('0.98', '0.01')
              : responseText,
          {
            status,
            headers: {
              'content-type': 'application/json',
              ...(encoding ? { 'content-encoding': encoding } : {}),
              ...(missingId ? {} : { 'x-generation-id': id }),
            },
          },
        );
      }
      const receipt = receipts.get(
        decodeURIComponent(url.pathname.slice('/v1/signature/'.length)),
      );
      if (url.pathname.startsWith('/v1/signature/') && receipt !== undefined) {
        gateway.expectRequestHeader(request);
        expect(url.searchParams.get('signing_algo')).toBe('ed25519');
        signaturePaths.push(url.pathname);
        if (failSignatureOnce && signaturePaths.length === 1)
          return new Response('', { status: 404 });
        if (unavailableSignatureOnce && signaturePaths.length === 1)
          return jsonResponse({
            error_code: 'not_found',
            message: 'Receipt not yet available',
          });
        return jsonResponse(receipt);
      }
      return chatFetch(request);
    };
    return { gateway, fetch, requests, signaturePaths };
  }

  function officialClient(client: { fetch: typeof globalThis.fetch }) {
    return new TypeSafeClient({
      apiKey: 'external-key',
      baseURL: 'https://gateway.test',
      fetch: client.fetch,
      compression: false,
      retry: { maxRetries: 0 },
      timeout: 60_000,
    });
  }

  const officialRequest = {
    model,
    state: { message: 'Charged twice — please help 🌎' },
    questions: {
      billing: noul('Is this about billing?'),
      team: choice('Choose a team.', {
        billing: null,
        support: 'Other issues',
      }),
      urgency: score('Rate the urgency.', ['Low', 'High']),
    },
  };

  const imagePart = {
    type: 'image_url',
    image_url: { url: 'data:image/png;base64,ZmFrZS1pbWFnZQ==' },
  };
  const imageRequest = {
    model,
    state: { canvas: imagePart },
    questions: {
      region: {
        type: 'box' as const,
        instructions: ['Locate the rectangle', imagePart],
      },
      present: {
        type: 'noul' as const,
        instructions: 'Does the canvas match?',
        criteria: { true: imagePart },
      },
    },
  };
  const boxBounds = { top: 0.31, bottom: 0.69, left: 0.25, right: 0.75 };

  test.each([undefined, null, 0.82])(
    'preserves JSON images and verifies Box receipts with confidence %s',
    async (confidence) => {
      const answer = {
        type: 'box',
        box: { ...boxBounds, future: 'preserved' },
        ...(confidence === undefined ? {} : { confidence }),
        future: { preserved: true },
      };
      const response = {
        ...decisionResponse,
        answers: { region: answer, present: { type: 'noul', noul: 0.98 } },
      };
      const fixture = decisionGateway({ response });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      const result = await client.systemone.create(imageRequest);
      expect(await fixture.requests[0].json()).toEqual(imageRequest);
      expect(result.data.answers.region).toEqual(answer);
      if (result.data.answers.region.type !== 'box')
        throw new Error('expected box');
      result.data.answers.region.box.top = 0;
      await expect(
        client.verifyResponse(result.decisionId),
      ).resolves.toMatchObject({
        signatureKind: 'gateway',
      });
      expect(fixture.requests).toHaveLength(1);
    },
  );

  test('TypeSafe SDK forwards OpenRouter image parts and verifies Box receipts', async () => {
    const fixture = decisionGateway({
      response: {
        ...decisionResponse,
        answers: { region: { type: 'box', box: boxBounds, confidence: 0.82 } },
      },
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const request = {
      model,
      state: [imagePart],
      questions: { region: box('Locate the rectangle') },
    };
    const { data, response } = await officialClient(client)
      .systemOne(request)
      .withResponse();
    expect(await fixture.requests[0].json()).toEqual(request);
    expect(data.answers.region.box).toEqual(boxBounds);
    const id = response.headers.get('x-generation-id');
    if (!id) throw new Error('missing receipt ID');
    await expect(client.verifyResponse(id)).resolves.toMatchObject({
      signatureKind: 'gateway',
    });
    expect(fixture.requests).toHaveLength(1);
  });

  test.each(['native', 'fetch'])(
    '%s preserves JSON assets, reference strings, and receipt bytes',
    async (entrypoint) => {
      const request = {
        model,
        assets: {
          '<photo>': { format: 'png', data_base64: 'ZmFrZS1pbWFnZQ==' },
        },
        state: { '<photo>': ['<photo>', imagePart] },
        questions: {
          region: { type: 'box', instructions: 'Locate <photo> — now' },
          match: {
            type: 'score',
            instructions: 'Rate the match.',
            criteria: ['Different', '<photo>'],
          },
        },
      } satisfies SystemOneRequest;
      const legend = { '0': 'Different', '1': '<photo>' };
      const fixture = decisionGateway({
        response: {
          ...decisionResponse,
          answers: {
            region: { type: 'box', box: boxBounds },
            match: {
              type: 'score',
              score: 1,
              confidence: 0.9,
              probabilities: { '0': 0.1, '1': 0.9 },
              legend,
            },
          },
        },
      });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      const body =
        entrypoint === 'native'
          ? JSON.stringify(request)
          : `${JSON.stringify(request, null, 2)}\n`;
      let id: string;
      if (entrypoint === 'native') {
        const result = await client.systemone.create(request);
        expect(result.data.answers.match).toMatchObject({ legend });
        id = result.decisionId;
      } else {
        const response = await client.fetch(`${baseUrl}systemone`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body,
        });
        expect((await response.json()).answers.match.legend).toEqual(legend);
        id = response.headers.get('x-generation-id') ?? '';
      }
      expect(await fixture.requests[0].text()).toBe(body);
      await expect(client.verifyResponse(id)).resolves.toMatchObject({
        signatureKind: 'gateway',
      });
      expect(fixture.requests).toHaveLength(1);
    },
  );

  test.each([
    { type: 'box' },
    { type: 'box', box: null },
    { type: 'box', box: { bottom: 1, left: 0, right: 1 } },
    ...[null, true, '0.31'].map((top) => ({
      type: 'box',
      box: { ...boxBounds, top },
    })),
    { type: 'box', box: boxBounds, confidence: '0.82' },
  ])(
    'rejects malformed Box answer %j without retaining a receipt',
    async (answer) => {
      const fixture = decisionGateway({
        response: {
          ...decisionResponse,
          answers: { region: answer },
        },
      });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      await expect(client.systemone.create(imageRequest)).rejects.toMatchObject(
        {
          failure: { code: 'api.invalid_response' },
        },
      );
      await expect(
        client.verifyResponse('decision-receipt'),
      ).rejects.toMatchObject({
        failure: { code: 'api.completion_not_found' },
      });
      expect(fixture.requests).toHaveLength(1);
    },
  );

  test.each(['native', 'official'])(
    '%s System One client verifies a response decoded by Fetch',
    async (api) => {
      const fixture = decisionGateway({ encoding: 'br' });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      let id: string;
      if (api === 'native') {
        const result = await client.systemone.create(decisionRequest);
        expect(result.data).toEqual(decisionResponse);
        id = result.decisionId;
      } else {
        const { data, response } = await officialClient(client)
          .systemOne(officialRequest)
          .withResponse();
        expect(data.answers.billing.noul).toBe(0.98);
        expect(response.headers.has('content-encoding')).toBe(false);
        id = response.headers.get('x-generation-id') ?? '';
      }
      expect(id).toBe('decision-receipt');
      await expect(client.verifyResponse(id)).resolves.toMatchObject({
        id,
        signatureKind: 'gateway',
      });
      expect(fixture.requests).toHaveLength(1);
    },
  );

  test.each([false, true])(
    'TypeSafe SDK uses the pinned transport and header receipt (provider TEE: %s)',
    async (tee) => {
      const fixture = decisionGateway({
        tee,
        includeModelPublicKey: true,
        decisionId: 'header-receipt',
      });
      mockNodeGatewayAttestation({ gateway: fixture.gateway });
      const unpinned = jest
        .spyOn(globalThis, 'fetch')
        .mockRejectedValue(new Error('Must use pinned transport'));
      const client = new TestNodeInferenceClient(
        {
          ...inferenceClientOptions(fixture.gateway),
          e2ee: false,
          apiKey: 'owner-key',
        },
        fixture.fetch,
      );
      const typesafe = officialClient(client);
      const { data, response, requestId } = await typesafe
        .systemOne(officialRequest, {
          headers: { 'x-model-pub-key': 'stale', 'x-client-pub-key': 'stale' },
        })
        .withResponse();
      expect(data.answers.billing.noul).toBe(0.98);
      expect(data.answers.team.choice).toBe('billing');
      expect(data.answers.urgency.score).toBe(0.6);
      expect(requestId).toBeUndefined(); // Upstream request ID is not the NEAR receipt.
      Object.assign(data.answers.billing, { noul: 0 });
      const id = response.headers.get('x-generation-id');
      expect(id).toBe('header-receipt');
      if (id === null) throw new Error('Missing receipt ID');
      const verified = await client.verifyResponse(id);
      expect(verified.signatureKind).toBe(tee ? 'provider_tee' : 'gateway');
      await expect(
        client.verifyResponse('decision-receipt'),
      ).rejects.toMatchObject({
        failure: { code: 'api.completion_not_found' },
      });
      await typesafe.systemOne(officialRequest);
      expect(fixture.gateway.state.gatewayAttestationRequests).toBe(1);
      expect(fixture.requests).toHaveLength(2);
      for (const request of fixture.requests) {
        expect(request.headers.get('authorization')).toBe('Bearer owner-key');
        expect(request.headers.get('x-model-pub-key')).toBe(
          tee ? keyHex(keyPair(2).publicKey) : null,
        );
        expect(request.headers.has('x-client-pub-key')).toBe(false);
        expect(request.headers.get('accept-encoding')).toBe('identity');
        expect(request.headers.get('x-no-aliasing')).toBe('true');
        expect(JSON.parse(await request.text())).toEqual(officialRequest);
      }
      expect(unpinned).not.toHaveBeenCalled();
      expect(client.pinnedSpkiFingerprints).toEqual([tlsFingerprint]);
    },
  );

  test.each(['tamper', 'signer'])(
    'TypeSafe SDK receipt rejects %s without repeating inference',
    async (fault) => {
      const fixture = decisionGateway({
        tee: true,
        includeModelPublicKey: true,
        tamper: fault === 'tamper',
        secondSigner: fault === 'signer',
        encoding: 'br',
      });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      const { response } = await officialClient(client)
        .systemOne(officialRequest)
        .withResponse();
      const id = response.headers.get('x-generation-id');
      if (id === null) throw new Error('Missing receipt ID');
      await expect(client.verifyResponse(id)).rejects.toBeInstanceOf(
        VerificationError,
      );
      expect(fixture.requests).toHaveLength(1);
    },
  );

  test.each(['status', 'id'])(
    'TypeSafe SDK surfaces %s failures without retries',
    async (fault) => {
      const fixture = decisionGateway({
        status: fault === 'status' ? 503 : 200,
        missingId: fault === 'id',
      });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      await expect(
        officialClient(client).systemOne(officialRequest),
      ).rejects.toMatchObject({
        cause: {
          failure: {
            code:
              fault === 'status' ? 'api.http_status' : 'api.invalid_response',
          },
        },
      });
      await expect(
        client.verifyResponse('decision-receipt'),
      ).rejects.toMatchObject({
        failure: { code: 'api.completion_not_found' },
      });
      expect(fixture.requests).toHaveLength(1);
      expect(fixture.signaturePaths).toHaveLength(0);
    },
  );

  test('TypeSafe SDK fails before inference when model key verification fails', async () => {
    const fixture = decisionGateway({
      tee: true,
      includeModelPublicKey: false,
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    await expect(
      officialClient(client).systemOne(officialRequest),
    ).rejects.toMatchObject({
      cause: { failure: { code: 'e2ee.model_public_key_required' } },
    });
    expect(fixture.requests).toHaveLength(0);
    expect(fixture.gateway.state.gatewayAttestationRequests).toBe(1);
  });

  test.each(['e2ee', 'ohttp'])(
    'TypeSafe SDK rejects %s before I/O',
    async (option) => {
      const fixture = decisionGateway();
      const network = jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
        [option]: true,
      });
      await expect(
        officialClient(client).systemOne(officialRequest),
      ).rejects.toMatchObject({
        cause: { failure: { code: 'api.invalid_input' } },
      });
      expect(network).not.toHaveBeenCalled();
    },
  );

  test('raw System One preserves JSON whitespace and query parameters', async () => {
    const fixture = decisionGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const body = `\n${JSON.stringify(officialRequest, null, 2)}\n`;
    const response = await client.fetch(`${baseUrl}systemone?trace=test`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    });
    const id = response.headers.get('x-generation-id');
    if (id === null) throw new Error('Missing receipt ID');
    await client.verifyResponse(id);
    expect(await fixture.requests[0].text()).toBe(body);
    expect(new URL(fixture.requests[0].url).searchParams.get('trace')).toBe(
      'test',
    );
  });

  test.each([
    ['GET', `${baseUrl}systemone`, {}, undefined],
    ['POST', 'https://other.test/v1/systemone', {}, '{}'],
    ['POST', `${baseUrl}responses`, {}, '{}'],
    [
      'POST',
      `${baseUrl}systemone`,
      { 'content-type': 'multipart/form-data' },
      '{}',
    ],
    [
      'POST',
      `${baseUrl}systemone`,
      { 'content-type': 'application/json', 'content-encoding': 'zstd' },
      'compressed',
    ],
    [
      'POST',
      `${baseUrl}systemone`,
      { 'content-type': 'application/json' },
      '{',
    ],
    [
      'POST',
      `${baseUrl}systemone`,
      { 'content-type': 'application/json' },
      JSON.stringify({ model, stream: false }),
    ],
  ] as const)(
    'rejects unsupported raw System One input %s %s %j before I/O',
    async (method, url, headers, body) => {
      const fixture = decisionGateway();
      const network = jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      await expect(
        client.fetch(url, { method, headers, body }),
      ).rejects.toMatchObject({ failure: { code: 'api.invalid_input' } });
      expect(network).not.toHaveBeenCalled();
    },
  );

  test('cancels a stalled System One request body before preflight', async () => {
    const fixture = decisionGateway();
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const controller = new AbortController();
    const reason = new Error('caller cancelled request body');
    let ready!: () => void;
    const reading = new Promise<void>((resolve) => {
      ready = resolve;
    });
    const cancel = jest.fn();
    const init = {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: controller.signal,
      duplex: 'half',
      body: new ReadableStream<Uint8Array>({
        start(stream) {
          stream.enqueue(
            new TextEncoder().encode(JSON.stringify(decisionRequest)),
          );
        },
        pull: ready,
        cancel,
      }),
    };
    const pending = client.fetch(new Request(`${baseUrl}systemone`, init));
    const rejected = expect(pending).rejects.toBe(reason);
    await reading;
    controller.abort(reason);
    await rejected;
    expect(cancel).toHaveBeenCalledWith(reason);
    expect(fetch).not.toHaveBeenCalled();
  }, 2000);

  test.each(['fetch', 'body'])(
    'preserves a caller abort reason during decision %s',
    async (phase) => {
      const fixture = decisionGateway();
      const controller = new AbortController();
      const reason = new Error('caller cancelled decision');
      let ready!: () => void;
      const started = new Promise<void>((resolve) => {
        ready = resolve;
      });
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(async (input, init) => {
          const request = new Request(input, init);
          if (new URL(request.url).pathname !== '/v1/systemone')
            return fixture.fetch(request);
          if (phase === 'fetch')
            return new Promise<Response>((_, reject) => {
              request.signal.addEventListener(
                'abort',
                () => reject(request.signal.reason),
                { once: true },
              );
              ready();
            });
          return new Response(
            new ReadableStream({
              start(stream) {
                request.signal.addEventListener(
                  'abort',
                  () => stream.error(request.signal.reason),
                  { once: true },
                );
                ready();
              },
            }),
            { headers: { 'x-generation-id': 'cancelled' } },
          );
        });
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      const pending = client.systemone.create(decisionRequest, {
        signal: controller.signal,
      });
      const rejected = expect(pending).rejects.toBe(reason);
      await started;
      controller.abort(reason);
      await rejected;
      expect(fixture.signaturePaths).toHaveLength(0);
    },
  );

  test('verifies a decision when multiple reports share the selected signer', async () => {
    const fixture = decisionGateway({ tee: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const request = new Request(input, init);
      const response = await fixture.fetch(request);
      const url = new URL(request.url);
      if (
        url.pathname === '/v1/attestation/report' &&
        url.searchParams.has('model')
      ) {
        const body = await response.json();
        body.model_attestations.push({ ...body.model_attestations[0] });
        return jsonResponse(body);
      }
      return response;
    });
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const preflight = await client.verify(model);
    expect(preflight.models).toHaveLength(2);
    const result = await client.systemone.create(decisionRequest);
    const verified = await client.verifyResponse(result.decisionId);
    expect(verified.attestation).toBe(preflight.models[0]);
    if (verified.signatureKind !== 'provider_tee')
      throw new Error('Expected model receipt');
    expect(verified.attestations).toEqual(preflight.models);
    expect(fixture.requests[0].headers.get('x-model-pub-key')).toBe(
      preflight.models[0].signingPublicKey,
    );
  });

  test('rejects a decision signed by another preflight-verified model key', async () => {
    const fixture = decisionGateway({
      tee: true,
      secondSigner: true,
      includeModelPublicKey: true,
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const result = await client.systemone.create(decisionRequest);
    await expect(
      client.verifyResponse(result.decisionId),
    ).rejects.toMatchObject({
      failure: { code: 'signature.signer_mismatch' },
    });
  });

  test.each([false, true])(
    'verifies exact response bytes (provider TEE: %s) through pinned Node transport',
    async (tee) => {
      const fixture = decisionGateway({ tee });
      mockNodeGatewayAttestation({ gateway: fixture.gateway });
      const unpinned = jest
        .spyOn(globalThis, 'fetch')
        .mockRejectedValue(new Error('Must use pinned transport'));
      const client = new TestNodeInferenceClient(
        {
          ...inferenceClientOptions(fixture.gateway),
          e2ee: false,
          headers: {
            [aggregatorHeader.name]: aggregatorHeader.value,
            'x-model-pub-key': 'stale',
            'x-signing-algo': 'ed25519',
            'x-client-pub-key': 'stale',
            'x-encryption-version': '2',
            'x-encrypt-all-fields': 'true',
          },
        },
        fixture.fetch,
      );
      const result = await client.systemone.create(decisionRequest, {
        headers: {
          'Content-Length': '0',
          'Content-Encoding': 'gzip',
          'Content-MD5': 'old-body',
          Digest: 'sha-256=old-body',
          'Content-Digest': 'sha-256=:old-body:',
          'Repr-Digest': 'sha-256=:old-body:',
        },
      });
      expect(result.data).toMatchObject(decisionResponse);
      expect(result.decisionId).toBe('decision-receipt');
      // Verification is bound to captured bytes even when the displayed value is edited.
      result.data.model = 'caller-edited';
      const verified = await client.verifyResponse(result.decisionId);
      expect(verified.id).toBe(result.decisionId);
      expect(verified.completionId).toBe(result.decisionId);
      expect(verified.signatureKind).toBe(tee ? 'provider_tee' : 'gateway');
      expect(verified.attestation.signer.signingAddress).toBe(
        keyHex(keyPair(tee ? 2 : 1).publicKey),
      );
      expect(await client.verifyResponse(result.decisionId)).toBe(verified);
      expect(fixture.signaturePaths).toEqual([
        '/v1/signature/decision-receipt',
      ]);
      expect(fixture.requests).toHaveLength(1);
      expect(JSON.parse(await fixture.requests[0].text())).toEqual(
        decisionRequest,
      );
      for (const name of [
        'x-signing-algo',
        'x-client-pub-key',
        'x-encryption-version',
        'x-encrypt-all-fields',
        'content-length',
        'content-encoding',
        'content-md5',
        'digest',
        'content-digest',
        'repr-digest',
      ])
        expect(fixture.requests[0].headers.has(name)).toBe(false);
      expect(fixture.requests[0].headers.get('x-model-pub-key')).toBe(
        tee ? keyHex(keyPair(2).publicKey) : null,
      );
      expect(fixture.requests[0].headers.get('x-no-aliasing')).toBe('true');
      expect(client.pinnedSpkiFingerprints).toEqual([tlsFingerprint]);
      expect(unpinned).not.toHaveBeenCalled();
    },
  );

  test('requires a model public key before sending a self-hosted decision', async () => {
    const fixture = decisionGateway({
      tee: true,
      includeModelPublicKey: false,
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    await expect(
      client.systemone.create(decisionRequest),
    ).rejects.toMatchObject({
      failure: { code: 'e2ee.model_public_key_required' },
    });
    expect(fixture.requests).toHaveLength(0);
  });

  test('verifies the Gateway before fetching model evidence for decisions', async () => {
    const fixture = decisionGateway({ tee: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    let releaseGateway!: () => void;
    const gatewayPending = new Promise<void>((resolve) => {
      releaseGateway = resolve;
    });
    let gatewayStarted!: () => void;
    const gatewayReady = new Promise<void>((resolve) => {
      gatewayStarted = resolve;
    });
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
      gatewayVerification: {
        verifiers: {
          tdxQuote: async (quote) => {
            gatewayStarted();
            await gatewayPending;
            return fixture.gateway.tdxQuoteVerifier(quote);
          },
        },
      },
      modelVerification: {
        verifiers: {
          tdxQuote: async (quote) => {
            const verified = await fixture.gateway.tdxQuoteVerifier(quote);
            return verified;
          },
        },
      },
    });

    const decision = client.systemone.create(decisionRequest);
    try {
      await gatewayReady;
      expect(fixture.gateway.state.metadataModels).toEqual([]);
      expect(fixture.gateway.state.modelAttestationRequests).toBe(0);
      expect(fixture.requests).toHaveLength(0);
    } finally {
      releaseGateway();
    }
    const result = await decision;
    await client.verifyResponse(result.decisionId);
    expect(fixture.requests).toHaveLength(1);
  });

  test.each([false, true])(
    'rejects tampering (provider TEE: %s)',
    async (tee) => {
      const fixture = decisionGateway({ tee, tamper: true, encoding: 'br' });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      const result = await client.systemone.create(decisionRequest);
      await expect(
        client.verifyResponse(result.decisionId),
      ).rejects.toMatchObject({
        failure: { code: 'signature.payload_mismatch' },
      });
      expect(fixture.requests).toHaveLength(1);
    },
  );

  test('retries only a transient receipt lookup, never inference', async () => {
    const fixture = decisionGateway({ failSignatureOnce: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const result = await client.systemone.create(decisionRequest);
    await expect(
      client.verifyResponse(result.decisionId),
    ).rejects.toMatchObject({ retryable: true });
    await expect(
      client.verifyResponse(result.decisionId),
    ).resolves.toMatchObject({
      signatureKind: 'gateway',
    });
    expect(fixture.requests).toHaveLength(1);
    expect(fixture.signaturePaths).toHaveLength(2);
  });

  test('retries an unavailable receipt without repeating inference', async () => {
    const fixture = decisionGateway({ unavailableSignatureOnce: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const result = await client.systemone.create(decisionRequest);
    await expect(
      client.verifyResponse(result.decisionId),
    ).rejects.toMatchObject({
      failure: { code: 'api.completion_signature_unavailable' },
    });
    expect(retainedCapture(client, result.decisionId)).toBeDefined();
    await expect(
      client.verifyResponse(result.decisionId),
    ).resolves.toMatchObject({
      signatureKind: 'gateway',
    });
    expect(fixture.requests).toHaveLength(1);
    expect(fixture.signaturePaths).toHaveLength(2);
    expect(retainedCapture(client, result.decisionId)).toBeUndefined();
  });

  test.each([false, true])(
    'rejects an incompatible Gateway signer before a decision (provider TEE: %s)',
    async (tee) => {
      const fixture = decisionGateway({
        tee,
      });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        signingAlgo: 'ecdsa',
        ohttp: false,
        e2ee: false,
      });
      await expect(
        client.systemone.create(decisionRequest),
      ).rejects.toMatchObject({
        failure: { code: 'signature.signer_mismatch' },
      });
      expect(fixture.requests).toHaveLength(0);
      expect(fixture.signaturePaths).toHaveLength(0);
    },
  );

  test.each(['request', 'response_body'] as const)(
    'classifies a System One %s failure without making it retryable',
    async (reason) => {
      const fixture = decisionGateway();
      const cause = new Error('connection reset');
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(async (input, init) => {
          const url = input instanceof Request ? input.url : String(input);
          const response = await fixture.fetch(input, init);
          if (url.endsWith('/systemone')) {
            if (reason === 'request') throw cause;
            return new Response(
              new ReadableStream({
                start(controller) {
                  controller.error(cause);
                },
              }),
              response,
            );
          }
          return response;
        });
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      await expect(
        client.systemone.create(decisionRequest),
      ).rejects.toMatchObject({
        failure: {
          code: 'api.transport_failed',
          details: { resource: 'systemone', reason },
          retryable: false,
        },
        retryable: false,
        cause,
      });
      expect(fixture.requests).toHaveLength(1);
      expect(fixture.signaturePaths).toHaveLength(0);
    },
  );

  test.each([
    { status: 400, missingId: false, code: 'api.http_status' },
    { status: 200, missingId: true, code: 'api.invalid_response' },
  ])('preserves $code when response cleanup fails', async (scenario) => {
    for (const alreadyErrored of [false, true]) {
      const fixture = decisionGateway(scenario);
      const cause = new Error('response cleanup failed');
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(async (input, init) => {
          const url = input instanceof Request ? input.url : String(input);
          const response = await fixture.fetch(input, init);
          if (url.endsWith('/systemone')) {
            return new Response(
              new ReadableStream({
                start(controller) {
                  if (alreadyErrored) controller.error(cause);
                },
                cancel() {
                  return Promise.reject(cause);
                },
              }),
              response,
            );
          }
          return response;
        });
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      await expect(
        client.systemone.create(decisionRequest),
      ).rejects.toMatchObject({
        name: 'ApiError',
        failure: { code: scenario.code },
        retryable: false,
      });
      expect(fixture.requests).toHaveLength(1);
      expect(fixture.signaturePaths).toHaveLength(0);
    }
  });

  test.each([
    { missingId: true },
    { decisionId: '' },
    { malformed: true },
    { status: 429 },
  ])(
    'rejects invalid/failed responses without replay: %j',
    async (scenario) => {
      const fixture = decisionGateway(scenario);
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      await expect(
        client.systemone.create(decisionRequest),
      ).rejects.toMatchObject({ name: 'ApiError' });
      expect(fixture.requests).toHaveLength(1);
      expect(fixture.signaturePaths).toHaveLength(0);
    },
  );

  test.each([{ e2ee: true }, { e2ee: false, ohttp: true as const }])(
    'rejects encryption before any network request: %j',
    async (options) => {
      const fetch = jest.spyOn(globalThis, 'fetch');
      const client = new InferenceClient({
        baseUrl,
        apiKey: 'test-key',
        ...options,
      });
      await expect(
        client.systemone.create(decisionRequest),
      ).rejects.toMatchObject({ failure: { code: 'api.invalid_input' } });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  test.each([true, false])(
    'rejects runtime stream=%s before preflight',
    async (stream) => {
      const fetch = jest.spyOn(globalThis, 'fetch');
      const client = new InferenceClient({ baseUrl, apiKey: 'test-key' });
      const request = { ...decisionRequest, stream };

      await expect(client.systemone.create(request)).rejects.toMatchObject({
        failure: { code: 'api.invalid_input' },
      });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  test('rejects pre-aborted calls before any network request', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch');
    const client = new InferenceClient({ baseUrl, apiKey: 'test-key' });
    const signal = AbortSignal.abort(new Error('cancelled'));
    await expect(
      client.systemone.create(decisionRequest, { signal }),
    ).rejects.toThrow('cancelled');
    expect(fetch).not.toHaveBeenCalled();
  });

  test('enforces deployment policy before sending private state to an external provider', async () => {
    const fixture = decisionGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
      deploymentPolicy: () => undefined,
    });
    await expect(
      client.systemone.create(decisionRequest),
    ).rejects.toMatchObject({
      failure: { code: 'policy.model_attestation_required' },
    });
    expect(fixture.requests).toHaveLength(0);
  });

  test('uses an opaque generation ID when the JSON body has no ID', async () => {
    const decisionId = 'gen:decision.123/result?part=1';
    const fixture = decisionGateway({ omitBodyId: true, decisionId });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const result = await client.systemone.create(decisionRequest);
    expect(result.decisionId).toBe(decisionId);
    expect(result.data.id).toBeUndefined();
    await expect(
      client.verifyResponse(result.decisionId),
    ).resolves.toMatchObject({
      id: decisionId,
      signatureKind: 'gateway',
    });
    expect(fixture.signaturePaths).toEqual([
      `/v1/signature/${encodeURIComponent(decisionId)}`,
    ]);
  });

  test('rejects invalid request headers through the returned promise', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch');
    const client = new InferenceClient({ baseUrl, apiKey: 'test-key' });

    const operation = client.systemone.create(decisionRequest, {
      headers: { 'x-client': 'invalid\nvalue' },
    });

    await expect(operation).rejects.toMatchObject({
      failure: {
        code: 'api.invalid_input',
        details: { field: 'headers', reason: 'invalid_header_value' },
      },
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  test('rejects a provider receipt whose signer has no verified attestation', async () => {
    const fixture = decisionGateway({ tee: true, unknownSigner: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const result = await client.systemone.create(decisionRequest);
    await expect(
      client.verifyResponse(result.decisionId),
    ).rejects.toMatchObject({
      failure: { code: 'signature.signer_mismatch' },
    });
  });

  test('a failed Gateway quote blocks inference', async () => {
    const fixture = decisionGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
      gatewayVerification: {
        verifiers: {
          tdxQuote: () => {
            throw new Error('invalid quote');
          },
        },
      },
    });
    await expect(client.systemone.create(decisionRequest)).rejects.toThrow();
    expect(fixture.requests).toHaveLength(0);
  });

  test.each(['constructor', 'prototype', '__proto__'])(
    'preserves %s as a question name, choice label, and structured context key',
    async (name) => {
      const request: SystemOneRequest = {
        model,
        state: { [name]: 'context' },
        questions: {
          [name]: { type: 'noul', instructions: { [name]: 'description' } },
          action: {
            type: 'choice',
            instructions: 'Choose an action.',
            criteria: { [name]: null, ok: 'Continue' },
          },
        },
      };
      const response = {
        model,
        answers: {
          [name]: { type: 'noul', noul: 0.8 },
          action: {
            type: 'choice',
            choice: name,
            confidence: 0.7,
            probabilities: { [name]: 0.7, ok: 0.3 },
          },
        },
        usage: { input_tokens: 10, output_tokens: 2 },
      };
      const fixture = decisionGateway({ response });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });

      const result = await client.systemone.create(request);
      const sent = await fixture.requests[0].json();
      expect(sent).toEqual(request);
      expect(result.data.answers).toEqual(response.answers);
      const verified = await client.verifyResponse(result.decisionId);
      expect(verified.signatureKind).toBe('gateway');
    },
  );

  test('leaves question business validation to the server', async () => {
    const fixture = decisionGateway({ status: 400 });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });

    await expect(
      client.systemone.create({ ...decisionRequest, questions: {} }),
    ).rejects.toMatchObject({
      failure: { code: 'api.http_status', details: { status: 400 } },
    });
    expect(fixture.requests).toHaveLength(1);
  });

  test.each([undefined, 100])(
    'shares concurrent decision preflight and honors the configured attestation TTL (%s)',
    async (attestationCacheTimeToLiveMs) => {
      const fixture = decisionGateway({ tee: true });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const now = jest.spyOn(Date, 'now').mockReturnValue(0);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
        attestationCacheTimeToLiveMs,
      });
      const ttl = attestationCacheTimeToLiveMs ?? 60 * 60 * 1000;

      await Promise.all([
        client.systemone.create(decisionRequest),
        client.systemone.create(decisionRequest),
      ]);
      now.mockReturnValue(ttl - 1);
      await client.systemone.create(decisionRequest);
      expect(fixture.gateway.state).toMatchObject({
        gatewayAttestationRequests: 1,
        modelAttestationRequests: 1,
        metadataModels: [model],
      });
      now.mockReturnValue(ttl);
      await client.systemone.create(decisionRequest);
      expect(fixture.gateway.state).toMatchObject({
        gatewayAttestationRequests: 2,
        modelAttestationRequests: 2,
        metadataModels: [model, model],
      });
      expect(fixture.requests).toHaveLength(4);
    },
  );

  test('disables decision attestation caching when the TTL is zero', async () => {
    const fixture = decisionGateway({ tee: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
      attestationCacheTimeToLiveMs: 0,
    });
    await client.systemone.create(decisionRequest);
    await client.systemone.create(decisionRequest);
    expect(fixture.gateway.state.gatewayAttestationRequests).toBe(2);
    expect(fixture.gateway.state.modelAttestationRequests).toBe(2);
  });

  test.each(['chat', 'systemone'])(
    'shares Chat and decision verification sessions (%s first)',
    async (first) => {
      const fixture = decisionGateway({
        tee: true,
        includeModelPublicKey: true,
      });
      jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      const order =
        first === 'chat' ? ['chat', 'systemone'] : ['systemone', 'chat'];
      for (const endpoint of [...order, ...order]) {
        if (endpoint === 'chat') {
          await client.verify(model);
          const completion = await client.chat.completions.create({
            model,
            messages: [{ role: 'user', content: 'Hello' }],
          });
          const verified = await client.verifyResponse(completion.id);
          expect(verified.attestation.signer.signingAddress).toBe(
            keyHex(keyPair(2).publicKey),
          );
        } else {
          const result = await client.systemone.create(decisionRequest);
          const verified = await client.verifyResponse(result.decisionId);
          expect(verified.attestation.signer.signingAddress).toBe(
            keyHex(keyPair(2).publicKey),
          );
        }
      }
      expect(fixture.gateway.state.gatewayAttestationRequests).toBe(1);
      expect(fixture.gateway.state.modelAttestationRequests).toBe(1);
      for (const request of fixture.gateway.state.completionRequestsSeen) {
        expect(request.headers.get('x-model-pub-key')).toBe(
          keyHex(keyPair(2).publicKey),
        );
      }
      expect(
        fixture.requests.every(
          (request) =>
            request.headers.get('x-model-pub-key') ===
            keyHex(keyPair(2).publicKey),
        ),
      ).toBe(true);
    },
  );

  test.each([false, true])(
    'clears an in-flight decision (external=%s)',
    async (external) => {
      const fixture = decisionGateway();
      let responseReady!: () => void;
      let resumeResponse!: () => void;
      const ready = new Promise<void>((resolve) => {
        responseReady = resolve;
      });
      const resume = new Promise<void>((resolve) => {
        resumeResponse = resolve;
      });
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(async (input, init) => {
          const response = await fixture.fetch(input, init);
          const url = new URL(
            input instanceof Request ? input.url : input.toString(),
          );
          if (url.pathname === '/v1/systemone') {
            responseReady();
            await resume;
          }
          return response;
        });
      const client = new InferenceClient({
        ...inferenceClientOptions(fixture.gateway),
        e2ee: false,
      });
      const pending = external
        ? client
            .fetch(new URL('systemone', baseUrl), {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify(decisionRequest),
            })
            .then(async (response) => {
              await response.arrayBuffer();
              return response.headers.get('x-generation-id') ?? '';
            })
        : client.systemone
            .create(decisionRequest)
            .then((result) => result.decisionId);
      await ready;
      client.clearResponseCache();
      resumeResponse();
      await expect(client.verifyResponse(await pending)).rejects.toMatchObject({
        failure: { code: 'api.completion_not_found' },
      });
      const next = await client.systemone.create(decisionRequest);
      await client.verifyResponse(next.decisionId);
      client.clearResponseCache();
    },
  );

  test('expires decision response records using the shared response TTL', async () => {
    const fixture = decisionGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(fixture.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
      responseCacheTimeToLiveMs: 100,
    });
    jest.useFakeTimers({
      doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'],
    });
    const result = await client.systemone.create(decisionRequest);
    const verification = client.verifyResponse(result.decisionId);
    expect(client.verifyResponse(result.decisionId)).toBe(verification);
    await verification;
    jest.advanceTimersByTime(99);
    await expect(
      client.verifyResponse(result.decisionId),
    ).resolves.toMatchObject({
      signatureKind: 'gateway',
    });
    jest.advanceTimersByTime(1);
    await expect(
      client.verifyResponse(result.decisionId),
    ).rejects.toMatchObject({
      failure: { code: 'api.completion_not_found' },
    });
    expect(fixture.signaturePaths).toHaveLength(1);
  });

  test('aborts a stalled decision preflight without cancelling another caller', async () => {
    const fixture = decisionGateway();
    const controller = new AbortController();
    let resume!: () => void;
    const blocked = new Promise<void>((resolve) => {
      resume = resolve;
    });
    let notifyStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      notifyStarted = resolve;
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const request = new Request(input, init);
      if (request.url.includes('/attestation/report')) {
        notifyStarted();
        await blocked;
      }
      return fixture.fetch(request);
    });
    const client = new InferenceClient({
      ...inferenceClientOptions(fixture.gateway),
      e2ee: false,
    });
    const cancelled = client.systemone.create(decisionRequest, {
      signal: controller.signal,
    });
    await started;
    const succeeding = client.systemone.create(decisionRequest);
    const reason = new Error('cancelled while waiting for evidence');
    controller.abort(reason);
    try {
      await expect(cancelled).rejects.toBe(reason);
      expect(fixture.requests).toHaveLength(0);
    } finally {
      resume();
    }
    const result = await succeeding;
    await client.verifyResponse(result.decisionId);
    expect(fixture.requests).toHaveLength(1);
    expect(fixture.gateway.state.gatewayAttestationRequests).toBe(1);
  });
});

describe('ECDSA System One', () => {
  afterEach(() => jest.restoreAllMocks());

  test.each(['gateway', 'provider_tee'] as const)(
    'verifies System One %s receipts with ECDSA',
    async (signatureKind) => {
      const gateway = createEcdsaGateway({ signatureKind });
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      const client = new InferenceClient({
        baseUrl,
        apiKey: 'test-token',
        signingAlgo: 'ecdsa',
        e2ee: false,
        gatewayVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
        modelVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
      });
      const result = await client.systemone.create({
        model,
        state: 'Charged twice',
        questions: {
          billing: { type: 'noul', instructions: 'Is this about billing?' },
        },
      });
      await expect(
        client.verifyResponse(result.decisionId),
      ).resolves.toMatchObject({ signatureKind });
      expect(gateway.state.attestationAlgorithms).toEqual(['ecdsa', 'ecdsa']);
      expect(gateway.state.signatureAlgorithms).toEqual(['ecdsa']);
      expect(gateway.state.completionHeaders[0].get('x-model-pub-key')).toBe(
        modelPublicKey,
      );
      expect(
        gateway.state.completionHeaders[0].get('x-signing-algo'),
      ).toBeNull();
    },
  );
});
