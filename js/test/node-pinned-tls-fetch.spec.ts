import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import type { ClientRequest, IncomingMessage } from 'node:http';
import * as https from 'node:https';
import { Readable } from 'node:stream';
import type { DetailedPeerCertificate } from 'node:tls';
import * as tls from 'node:tls';
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
};

function spkiFingerprint(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function incomingResponse(body: string): IncomingMessage {
  return Object.assign(Readable.from([Buffer.from(body)]), {
    statusCode: 200,
    statusMessage: 'OK',
    headers: { 'content-type': 'application/json', 'x-test': 'response' },
  }) as unknown as IncomingMessage;
}

function installHttpsRequests({
  peerCertificates,
  waitForAbort = false,
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
        callback?.(incomingResponse('{"ok":true}'));
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
