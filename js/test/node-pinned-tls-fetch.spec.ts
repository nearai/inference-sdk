import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import type { ClientRequest, IncomingMessage } from 'node:http';
import * as https from 'node:https';
import { Readable } from 'node:stream';
import type { DetailedPeerCertificate } from 'node:tls';
import * as tls from 'node:tls';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';
import { createPinnedTlsFetch } from '../src/node';

jest.mock('node:crypto', () => {
  const crypto =
    jest.requireActual<typeof import('node:crypto')>('node:crypto');
  class TestX509Certificate {
    readonly publicKey: {
      export: () => Buffer;
    };

    constructor(raw: Buffer) {
      this.publicKey = { export: () => raw };
    }
  }
  return { ...crypto, X509Certificate: TestX509Certificate };
});

jest.mock('node:https', () => ({
  ...jest.requireActual<typeof import('node:https')>('node:https'),
  request: jest.fn(),
}));

jest.mock('node:tls', () => ({
  ...jest.requireActual<typeof import('node:tls')>('node:tls'),
  checkServerIdentity: jest.fn(() => undefined),
}));

type HttpsRequestOptions = Parameters<typeof https.request>[1];
type HttpsResponseHandler = (response: IncomingMessage) => void;
type NativeRequestCall = {
  readonly url: string | URL;
  readonly options: HttpsRequestOptions;
  body?: Uint8Array;
};

type InstallHttpsRequestsParams = {
  readonly peerCertificates: readonly Uint8Array[];
  readonly waitForAbort?: boolean;
  readonly response?: IncomingMessage;
};

function spkiFingerprint(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function incomingResponse(body: string | Uint8Array): IncomingMessage {
  return Object.assign(Readable.from([Buffer.from(body)]), {
    statusCode: 200,
    statusMessage: 'OK',
    headers: { 'content-type': 'application/json', 'x-test': 'response' },
  }) as unknown as IncomingMessage;
}

function installHttpsRequests({
  peerCertificates,
  waitForAbort = false,
  response,
}: InstallHttpsRequestsParams): NativeRequestCall[] {
  const calls: NativeRequestCall[] = [];
  let nextPeerCertificate = 0;
  jest.mocked(https.request).mockImplementation(((
    url: string | URL,
    options: HttpsRequestOptions,
    callback?: HttpsResponseHandler,
  ) => {
    let onError: ((error: Error) => void) | undefined;
    const call: NativeRequestCall = { url, options };
    calls.push(call);
    const request = {
      once(event: string, listener: (error: Error) => void) {
        if (event === 'error') {
          onError = listener;
        }
        return request;
      },
      end(body?: Uint8Array) {
        call.body = body;
        if (waitForAbort) {
          options?.signal?.addEventListener(
            'abort',
            () => {
              const error = new Error('Request aborted');
              error.name = 'AbortError';
              onError?.(error);
            },
            { once: true },
          );
          return;
        }
        const peerCertificate = peerCertificates[nextPeerCertificate];
        nextPeerCertificate += 1;
        if (peerCertificate === undefined) {
          onError?.(new Error('Missing test peer certificate'));
          return;
        }
        const identityError = options?.checkServerIdentity?.('gateway.test', {
          raw: Buffer.from(peerCertificate),
        } as DetailedPeerCertificate);
        if (identityError !== undefined) {
          onError?.(identityError);
          return;
        }
        callback?.(response ?? incomingResponse('{"ok":true}'));
      },
      destroy(error: Error) {
        onError?.(error);
        return request;
      },
    };
    return request as unknown as ClientRequest;
  }) as never);
  return calls;
}

describe('createPinnedTlsFetch', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('checks every TLS peer and preserves Fetch request and response data', async () => {
    const matchingSpki = Buffer.from('matching-spki');
    const unexpectedSpki = Buffer.from('unexpected-spki');
    const requests = installHttpsRequests({
      peerCertificates: [matchingSpki, unexpectedSpki],
    });
    const fetch = createPinnedTlsFetch(spkiFingerprint(matchingSpki));

    const response = await fetch('https://gateway.test/v1/chat/completions', {
      method: 'POST',
      headers: {
        authorization: 'Bearer test',
        'content-type': 'application/json',
        'accept-encoding': 'gzip',
      },
      body: '{"model":"glm-5.3-flash"}',
    });

    expect(response.headers.get('content-type')).toBe('application/json');
    expect(response.headers.get('x-test')).toBe('response');
    await expect(response.json()).resolves.toEqual({ ok: true });
    const firstRequest = requests[0];
    if (firstRequest === undefined) {
      throw new Error('Expected a pinned HTTPS request');
    }
    expect(firstRequest.url).toBe('https://gateway.test/v1/chat/completions');
    expect(firstRequest.options?.method).toBe('POST');
    expect(firstRequest.options?.headers).toMatchObject({
      authorization: 'Bearer test',
      'content-type': 'application/json',
      'accept-encoding': 'identity',
    });
    expect(firstRequest.options?.rejectUnauthorized).toBe(true);
    expect(firstRequest.body).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(firstRequest.body)).toBe(
      '{"model":"glm-5.3-flash"}',
    );

    await expect(
      fetch('https://gateway.test/v1/attestation/report'),
    ).rejects.toMatchObject({
      failure: { code: 'binding.spki_fingerprint_mismatch' },
    });
    expect(jest.mocked(tls.checkServerIdentity)).toHaveBeenCalledTimes(2);
    expect(requests).toHaveLength(2);
  });

  test('forwards an AbortSignal to the native HTTPS request', async () => {
    const matchingSpki = Buffer.from('matching-spki');
    const requests = installHttpsRequests({
      peerCertificates: [matchingSpki],
      waitForAbort: true,
    });
    const fetch = createPinnedTlsFetch(spkiFingerprint(matchingSpki));
    const controller = new AbortController();

    const pending = fetch('https://gateway.test/v1/chat/completions', {
      signal: controller.signal,
    });
    controller.abort();

    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(requests).toHaveLength(1);
  });

  test.each([
    ['gzip', gzipSync],
    ['br', brotliCompressSync],
  ] as const)(
    'decodes %s without changing response bytes',
    async (encoding, compress) => {
      const spki = Buffer.from('matching-spki');
      const body = Buffer.from(' \n{"ok": true}\n');
      const wire = compress(body);
      const incoming = incomingResponse(wire);
      incoming.headers['content-encoding'] = encoding;
      incoming.headers['content-length'] = String(wire.length);
      installHttpsRequests({ peerCertificates: [spki], response: incoming });

      const response = await createPinnedTlsFetch(spkiFingerprint(spki))(
        'https://gateway.test/v1/systemone',
      );
      expect(Buffer.from(await response.arrayBuffer())).toEqual(body);
      expect(response.headers.has('content-encoding')).toBe(false);
      expect(response.headers.has('content-length')).toBe(false);
      expect(response.headers.get('x-test')).toBe('response');
    },
  );

  test.each([
    ['gzip', gzipSync],
    ['br', brotliCompressSync],
  ] as const)('propagates %s decoding errors', async (encoding, compress) => {
    for (const wire of [
      Buffer.from('not compressed'),
      Buffer.alloc(0),
      compress(Buffer.from('{"ok":true}')).subarray(0, -1),
    ]) {
      const spki = Buffer.from('matching-spki');
      const incoming = incomingResponse(wire);
      incoming.headers['content-encoding'] = encoding;
      installHttpsRequests({ peerCertificates: [spki], response: incoming });

      const response = await createPinnedTlsFetch(spkiFingerprint(spki))(
        'https://gateway.test/v1/systemone',
      );
      await expect(response.arrayBuffer()).rejects.toThrow();
    }
  });

  test.each([
    [
      'gzip',
      (body: Buffer) => gzipSync(body, { finishFlush: constants.Z_SYNC_FLUSH }),
    ],
    [
      'br',
      (body: Buffer) =>
        brotliCompressSync(body, {
          finishFlush: constants.BROTLI_OPERATION_FLUSH,
        }),
    ],
  ] as const)(
    'streams %s before EOF and closes the source on cancel',
    async (encoding, compress) => {
      const spki = Buffer.from('matching-spki');
      const incoming = Object.assign(new Readable({ read() {} }), {
        statusCode: 200,
        headers: { 'content-encoding': encoding },
      }) as IncomingMessage;
      const firstEvent = Buffer.from('data: {"id":"chat-1"}\n\n');
      incoming.push(compress(firstEvent));
      installHttpsRequests({ peerCertificates: [spki], response: incoming });
      const response = await createPinnedTlsFetch(spkiFingerprint(spki))(
        'https://gateway.test/v1/chat/completions',
      );
      const reader = response.body?.getReader();
      expect(await reader?.read()).toEqual({
        value: new Uint8Array(firstEvent),
        done: false,
      });
      const closed = new Promise<void>((resolve) =>
        incoming.once('close', resolve),
      );
      await reader?.cancel();
      await closed;
      expect(incoming.destroyed).toBe(true);
    },
  );

  test('preserves compressed representation headers on a bodyless HEAD response', async () => {
    const spki = Buffer.from('matching-spki');
    const incoming = incomingResponse('');
    incoming.headers['content-encoding'] = 'gzip';
    incoming.headers['content-length'] = '100';
    installHttpsRequests({ peerCertificates: [spki], response: incoming });

    const response = await createPinnedTlsFetch(spkiFingerprint(spki))(
      'https://gateway.test/v1/model/example',
      { method: 'HEAD' },
    );
    await expect(response.text()).resolves.toBe('');
    expect(response.body).toBeNull();
    expect(response.headers.get('content-encoding')).toBe('gzip');
    expect(response.headers.get('content-length')).toBe('100');
  });

  test('accepts every verified peer fingerprint and rejects an unknown peer', async () => {
    const firstSpki = Buffer.from('first-model-spki');
    const secondSpki = Buffer.from('second-model-spki');
    const requests = installHttpsRequests({
      peerCertificates: [firstSpki, secondSpki, Buffer.from('unknown-spki')],
    });
    const fetch = createPinnedTlsFetch([
      spkiFingerprint(firstSpki),
      spkiFingerprint(secondSpki),
    ]);

    for (let index = 0; index < 2; index += 1) {
      const response = await fetch('https://model.test/v1/chat/completions');
      await expect(response.json()).resolves.toEqual({ ok: true });
    }
    await expect(
      fetch('https://model.test/v1/chat/completions'),
    ).rejects.toMatchObject({
      failure: { code: 'binding.spki_fingerprint_mismatch' },
    });
    expect(requests).toHaveLength(3);
    for (const request of requests) {
      expect(request.options?.rejectUnauthorized).toBe(true);
    }
  });

  test('does not let a matching pin bypass hostname verification', async () => {
    const matchingSpki = Buffer.from('matching-spki');
    installHttpsRequests({ peerCertificates: [matchingSpki] });
    const hostnameError = new Error('Certificate hostname does not match');
    jest.mocked(tls.checkServerIdentity).mockReturnValueOnce(hostnameError);
    const fetch = createPinnedTlsFetch([spkiFingerprint(matchingSpki)]);

    await expect(
      fetch('https://model.test/v1/attestation/report'),
    ).rejects.toBe(hostnameError);
  });

  test('requires at least one verified fingerprint', () => {
    expect(() => createPinnedTlsFetch([])).toThrow(
      expect.objectContaining({
        failure: { code: 'binding.spki_fingerprint_required' },
      }),
    );
  });
});
