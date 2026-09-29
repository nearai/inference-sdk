import {
  AEAD_AES_128_GCM,
  CipherSuite,
  KDF_HKDF_SHA256,
  KEM_DHKEM_X25519_HKDF_SHA256,
} from 'hpke';
import { ChunkedOHTTPServer, KeyConfig, frameChunk } from 'ohttp-ts';
import { createOhttpFetch } from '../src/core/ohttp-fetch';
import { ApiError, VerificationError } from '../src/utils/errors';

const BASE_URL = 'https://inference.example/v1/';
const URL = 'https://inference.example/v1/chat/completions?test=1';
let config: Uint8Array;
let server: ChunkedOHTTPServer;

beforeAll(async () => {
  const suite = new CipherSuite(
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    AEAD_AES_128_GCM,
  );
  const key = await KeyConfig.generate(suite, 1);
  config = KeyConfig.serialize(key);
  server = new ChunkedOHTTPServer([key]);
});

test('round-trips exact bytes, status and headers while exposing only configured outer auth', async () => {
  const requestBody = new Uint8Array([0, 1, 128, 255]);
  const responseBody = new Uint8Array([255, 0, 128, 7]);
  const abort = new AbortController();
  const transport = jest.fn<ReturnType<typeof fetch>, Parameters<typeof fetch>>(
    async (input, init) => {
      const outer = new Request(input, init);
      expect(outer.url).toBe('https://inference.example/ohttp');
      expect(outer.method).toBe('POST');
      expect(outer.credentials).toBe('include');
      expect(outer.redirect).toBe('error');
      expect(Object.fromEntries(outer.headers)).toEqual({
        authorization: 'Bearer test-token',
        'content-type': 'message/ohttp-chunked-req',
        'x-proxy-token': 'per-call-token',
      });
      const { request, context } = await server.decapsulateRequest(outer);
      expect(request.url).toBe(URL);
      expect(request.method).toBe('POST');
      expect(request.headers.get('x-model-pub-key')).toBe('private-model-key');
      expect(request.headers.get('x-client-pub-key')).toBe(
        'private-client-key',
      );
      expect(new Uint8Array(await request.arrayBuffer())).toEqual(requestBody);
      return context.encapsulateResponse(
        new Response(responseBody, {
          status: 418,
          headers: {
            'x-response': 'preserved',
            'content-type': 'application/octet-stream',
          },
        }),
      );
    },
  );
  const ohttp = createOhttpFetch({
    keyConfig: config,
    baseUrl: BASE_URL,
    fetch: transport,
    forwardedHeaders: ['X-Proxy-Token', 'X-Model-Pub-Key'],
  });
  const response = await ohttp(URL, {
    method: 'POST',
    headers: {
      authorization: 'Bearer test-token',
      'x-proxy-token': 'per-call-token',
      'x-model-pub-key': 'private-model-key',
      'x-client-pub-key': 'private-client-key',
      'content-type': 'application/octet-stream',
    },
    body: requestBody,
    credentials: 'include',
    signal: abort.signal,
  });
  expect(response.status).toBe(418);
  expect(response.headers.get('x-response')).toBe('preserved');
  expect(response.headers.get('content-type')).toBe('application/octet-stream');
  expect(new Uint8Array(await response.arrayBuffer())).toEqual(responseBody);
});

test.each(['valid', 'truncated', 'tampered'] as const)(
  'streams entity bytes and verifies the final chunk after the BHTTP terminator: %s',
  async (ending) => {
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    let finalFrame!: Uint8Array;
    const ohttp = createOhttpFetch({
      keyConfig: config,
      baseUrl: BASE_URL,
      fetch: async (input, init) => {
        const request = new Request(input, init);
        const decrypted = await server.decapsulate(
          new Uint8Array(await request.arrayBuffer()),
        );
        const context = await decrypted.createResponseContext();
        // RFC 9292: indeterminate response, status 200, empty headers,
        // one body chunk "hello", content terminator and empty trailers.
        const bhttp = new Uint8Array([
          3, 0x40, 0xc8, 0, 5, 104, 101, 108, 108, 111, 0, 0,
        ]);
        const firstFrame = frameChunk(await context.sealChunk(bhttp), false);
        finalFrame = frameChunk(
          await context.sealFinalChunk(new Uint8Array()),
          true,
        );
        return new Response(
          new ReadableStream<Uint8Array>({
            start(output) {
              controller = output;
              output.enqueue(context.responseNonce);
              output.enqueue(firstFrame);
            },
          }),
          { headers: { 'content-type': 'message/ohttp-chunked-res' } },
        );
      },
    });
    const response = await ohttp(URL);
    if (response.body === null) throw new Error('Expected a streaming body');
    const reader = response.body.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe('hello');
    if (ending !== 'truncated') {
      if (ending === 'tampered') finalFrame[finalFrame.length - 1] ^= 1;
      controller.enqueue(finalFrame);
    }
    controller.close();
    if (ending === 'valid') {
      await expect(reader.read()).resolves.toMatchObject({ done: true });
    } else {
      await expect(reader.read()).rejects.toMatchObject({
        failure: { code: 'ohttp.decryption_failed' },
      });
    }
  },
);

test.each([204, 205, 304])(
  'authenticates a bodyless %s response',
  async (status) => {
    const ohttp = createOhttpFetch({
      keyConfig: config,
      baseUrl: BASE_URL,
      fetch: async (input, init) => {
        const { context } = await server.decapsulateRequest(
          new Request(input, init),
        );
        return context.encapsulateResponse(new Response(null, { status }));
      },
    });
    const response = await ohttp(URL);
    expect(response.status).toBe(status);
    expect(response.body).toBeNull();
  },
);

test('preserves abort reasons and cancels a pending encrypted response', async () => {
  const abort = new AbortController();
  let begin!: () => void;
  const started = new Promise<void>((resolve) => {
    begin = resolve;
  });
  const canceled = jest.fn();
  const ohttp = createOhttpFetch({
    keyConfig: config,
    baseUrl: BASE_URL,
    fetch: async (input, init) => {
      const request = new Request(input, init);
      expect(request.signal.aborted).toBe(false);
      begin();
      return new Response(new ReadableStream({ cancel: canceled }), {
        headers: { 'content-type': 'message/ohttp-chunked-res' },
      });
    },
  });
  const pending = ohttp(URL, { signal: abort.signal });
  await started;
  const reason = new Error('caller stopped');
  abort.abort(reason);
  await expect(pending).rejects.toBe(reason);
  expect(canceled).toHaveBeenCalledWith(reason);
});

test.each(['cancel', 'abort'])(
  '%s while reading the decrypted body cancels the outer body',
  async (operation) => {
    const abort = new AbortController();
    const canceled = jest.fn();
    const ohttp = createOhttpFetch({
      keyConfig: config,
      baseUrl: BASE_URL,
      fetch: async (input, init) => {
        const request = new Request(input, init);
        const decrypted = await server.decapsulate(
          new Uint8Array(await request.arrayBuffer()),
        );
        const context = await decrypted.createResponseContext();
        const firstFrame = frameChunk(
          await context.sealChunk(new Uint8Array([3, 0x40, 0xc8, 0, 1, 65])),
          false,
        );
        return new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(context.responseNonce);
              controller.enqueue(firstFrame);
            },
            cancel: canceled,
          }),
          { headers: { 'content-type': 'message/ohttp-chunked-res' } },
        );
      },
    });
    const response = await ohttp(URL, { signal: abort.signal });
    const reason = new Error('no longer needed');
    if (operation === 'cancel') {
      if (response.body === null) throw new Error('Expected a streaming body');
      await response.body.cancel(reason);
    } else {
      abort.abort(reason);
      await expect(response.arrayBuffer()).rejects.toBe(reason);
    }
    expect(canceled).toHaveBeenCalledWith(reason);
  },
);

test('rejects a malformed key config before making requests', () => {
  const transport = jest.fn<
    ReturnType<typeof fetch>,
    Parameters<typeof fetch>
  >();
  expect(() =>
    createOhttpFetch({
      keyConfig: new Uint8Array([1]),
      baseUrl: BASE_URL,
      fetch: transport,
    }),
  ).toThrow(
    expect.objectContaining({ failure: { code: 'ohttp.key_config_invalid' } }),
  );
  expect(transport).not.toHaveBeenCalled();
});

test('wraps an outer HTTP failure with OHTTP resource metadata', async () => {
  const ohttp = createOhttpFetch({
    keyConfig: config,
    baseUrl: BASE_URL,
    fetch: async () => new Response(null, { status: 503 }),
  });
  await expect(ohttp(URL)).rejects.toMatchObject({
    failure: {
      code: 'api.http_status',
      details: { resource: 'ohttp', status: 503 },
    },
    retryable: true,
  });
});

test('wraps transport failure and never falls back to plaintext', async () => {
  const cause = new Error('connection failed');
  const transport = jest.fn<ReturnType<typeof fetch>, Parameters<typeof fetch>>(
    async () => {
      throw cause;
    },
  );
  const ohttp = createOhttpFetch({
    keyConfig: config,
    baseUrl: BASE_URL,
    fetch: transport,
  });
  await expect(ohttp(URL)).rejects.toMatchObject({
    failure: {
      code: 'api.transport_failed',
      details: { resource: 'ohttp', reason: 'request' },
    },
    cause,
  });
  expect(transport).toHaveBeenCalledTimes(1);
});

test('rejects a different target origin before sending', async () => {
  const transport = jest.fn<
    ReturnType<typeof fetch>,
    Parameters<typeof fetch>
  >();
  const ohttp = createOhttpFetch({
    keyConfig: config,
    baseUrl: BASE_URL,
    fetch: transport,
  });
  await expect(
    ohttp('https://other.example/v1/chat/completions'),
  ).rejects.toMatchObject({
    failure: { code: 'api.invalid_input' },
  });
  expect(transport).not.toHaveBeenCalled();
});

test.each([
  new VerificationError({ code: 'binding.spki_fingerprint_mismatch' }),
  new ApiError({
    code: 'api.http_status',
    details: { resource: 'ohttp', status: 401 },
    retryable: false,
  }),
])('preserves SDK failures from an underlying transport: %s', async (cause) => {
  const ohttp = createOhttpFetch({
    keyConfig: config,
    baseUrl: BASE_URL,
    fetch: async () => {
      throw cause;
    },
  });
  await expect(ohttp(URL)).rejects.toBe(cause);
});

test('uses global fetch when no transport is supplied', async () => {
  const transport = jest
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (input, init) => {
      const { context } = await server.decapsulateRequest(
        new Request(input, init),
      );
      return context.encapsulateResponse(new Response('default transport'));
    });
  try {
    const ohttp = createOhttpFetch({ keyConfig: config, baseUrl: BASE_URL });
    const response = await ohttp(URL);
    const body = await response.text();
    expect(body).toBe('default transport');
    expect(transport).toHaveBeenCalledTimes(1);
  } finally {
    transport.mockRestore();
  }
});
