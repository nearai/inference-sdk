import { createE2eeClientKeyPair } from '../src/core/e2ee';
import { prepareE2eeChatRequest } from '../src/core/e2ee-request';
import {
  type InferenceSession,
  type InferenceTransportOptions,
  VerifiedInferenceClientBase,
} from '../src/core/inference-client';

class Client extends VerifiedInferenceClientBase<string, string> {
  readonly verified: string[] = [];
  next = 0;
  response: (() => Response) | undefined;
  gate: Promise<void> | undefined;
  signatureGate: (() => Promise<void>) | undefined;
  modelKey: InferenceSession<string, string>['modelKey'];

  constructor(options: InferenceTransportOptions = {}) {
    super({ baseUrl: 'https://example.test/v1/', ...options });
  }

  protected async createVerificationState(
    model: string,
  ): Promise<InferenceSession<string, string>> {
    this.verified.push(model);
    await this.gate;
    return {
      attestationResult: model,
      ...(this.modelKey === undefined ? {} : { modelKey: this.modelKey }),
      transport: {
        fetch: async () =>
          this.response?.() ??
          Response.json({ id: `id-${++this.next}`, text: 'answer' }),
        fetchCompletionSignature: async () => {
          await this.signatureGate?.();
          return {
            kind: 'gateway',
            signedText: '',
            signature: '',
            signer: {
              signingAlgo: this.signingAlgo,
              signingAddress: '00'.repeat(32),
            },
          };
        },
      },
      verifyResponse: ({ id }) => id,
    };
  }

  send(model = 'm'): Promise<Response> {
    return this.fetch('https://example.test/v1/chat/completions', {
      method: 'POST',
      body: JSON.stringify({ model }),
    });
  }
}

describe('inference cache capacity', () => {
  test.each([0, -1, NaN, Infinity, 1.5])(
    'rejects invalid limits: %s',
    (value) => {
      for (const field of [
        'maxBodyBytes',
        'maxCacheEntries',
        'maxReceiptCacheBytes',
      ]) {
        expect(() => new Client({ [field]: value })).toThrow();
      }
    },
  );

  test('evicts completed sessions and receipts at the entry bound', async () => {
    const client = new Client({ maxCacheEntries: 1 });
    const first = await (await client.send('one')).json();
    const second = await (await client.send('two')).json();
    await expect(client.verifyResponse(first.id)).rejects.toMatchObject({
      failure: { code: 'api.completion_not_found' },
    });
    await expect(client.verifyResponse(second.id)).resolves.toBe(second.id);
    await client.verify('one');
    expect(client.verified).toEqual(['one', 'two', 'one']);
  });

  test('applies the byte budget and preserves a receipt when a new body is oversized', async () => {
    const client = new Client({ maxReceiptCacheBytes: 80 });
    const first = await (await client.send()).json();
    const second = await (await client.send()).json();
    await expect(client.verifyResponse(first.id)).rejects.toMatchObject({
      failure: { code: 'api.completion_not_found' },
    });
    client.response = () =>
      Response.json({ id: 'large', text: 'x'.repeat(100) });
    await expect((await client.send()).text()).rejects.toMatchObject({
      failure: { code: 'api.body_too_large' },
    });
    await expect(client.verifyResponse(second.id)).resolves.toBe(second.id);
  });

  test('counts caller-owned lookups against verification capacity', async () => {
    const client = new Client({ maxCacheEntries: 1 });
    let release = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    client.signatureGate = () => gate;
    const first = await (await client.send()).json();
    const pending = client.verifyResponse(first.id, {
      signal: new AbortController().signal,
    });
    try {
      await expect(client.verifyResponse(first.id)).rejects.toMatchObject({
        failure: { code: 'api.invalid_input' },
      });
    } finally {
      release();
      await pending;
    }
    await expect(client.verifyResponse(first.id)).resolves.toBe(first.id);
  });

  test.each(['count', 'bytes', 'expiry'] as const)(
    'preserves verification and its capacity after %s eviction',
    async (eviction) => {
      if (eviction === 'expiry') jest.useFakeTimers();
      const client = new Client({
        ...(eviction === 'count' ? { maxCacheEntries: 1 } : {}),
        ...(eviction === 'bytes' ? { maxReceiptCacheBytes: 80 } : {}),
        ...(eviction === 'expiry' ? { responseCacheTimeToLiveMs: 10 } : {}),
      });
      let signalStarted = () => {};
      const started = new Promise<void>((resolve) => {
        signalStarted = resolve;
      });
      let release = () => {};
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      client.signatureGate = () => {
        signalStarted();
        return gate;
      };
      const first = await (await client.send()).json();
      const verification = client.verifyResponse(first.id);
      try {
        await started;
        let second = first;
        if (eviction === 'expiry') {
          await jest.advanceTimersByTimeAsync(11);
        } else {
          second = await (await client.send()).json();
          await expect(client.verifyResponse(second.id)).rejects.toMatchObject({
            failure: {
              code:
                eviction === 'count'
                  ? 'api.invalid_input'
                  : 'api.completion_not_found',
            },
          });
        }
        await expect(client.verifyResponse(first.id)).rejects.toMatchObject({
          failure: { code: 'api.completion_not_found' },
        });
        release();
        await expect(verification).resolves.toBe(first.id);
        if (eviction !== 'count') second = await (await client.send()).json();
        await expect(client.verifyResponse(second.id)).resolves.toBe(second.id);
      } finally {
        release();
        await verification;
        jest.useRealTimers();
      }
    },
  );

  test('rejects a large request before preflight and bounds an unknown-length response', async () => {
    const client = new Client({ maxBodyBytes: 40 });
    await expect(client.send('x'.repeat(100))).rejects.toMatchObject({
      failure: { code: 'api.body_too_large' },
    });
    expect(client.verified).toHaveLength(0);
    let cancelled = false;
    client.response = () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('x'.repeat(100)));
          },
          cancel() {
            cancelled = true;
          },
        }),
      );
    await expect((await client.send()).text()).rejects.toMatchObject({
      failure: { code: 'api.body_too_large' },
    });
    expect(cancelled).toBe(true);
  });

  test.each([
    ['capacity', false],
    ['capacity', true],
    ['replacement', false],
    ['replacement', true],
  ] as const)(
    'reserves a stream during %s eviction (caller signal: %s)',
    async (eviction, callerSignal) => {
      const client = new Client({ maxReceiptCacheBytes: 300 });
      const releases: (() => void)[] = [];
      const gates = [0, 1].map(
        () => new Promise<void>((resolve) => releases.push(resolve)),
      );
      const waiting = eviction === 'capacity' ? [...gates] : [gates[1]];
      client.signatureGate = () => waiting.shift() ?? Promise.resolve();
      const jsonResponse = () =>
        Response.json({ id: `id-${++client.next}`, text: 'x'.repeat(150) });
      client.response = jsonResponse;
      const first =
        eviction === 'capacity'
          ? await (await client.send()).json()
          : undefined;
      const verifyingFirst =
        first === undefined ? undefined : client.verifyResponse(first.id);
      let verifyingStream: Promise<string> | undefined;
      let finish = () => {};
      try {
        client.response = () =>
          new Response(
            new ReadableStream({
              start(controller) {
                controller.enqueue(
                  new TextEncoder().encode(
                    `data: ${JSON.stringify({ id: 'stream', text: 'x'.repeat(150) })}\n\ndata: [DONE]\n\n`,
                  ),
                );
                finish = () => {
                  controller.close();
                  finish = () => {};
                };
              },
            }),
            { headers: { 'content-type': 'text/event-stream' } },
          );
        const response = await client.send();
        if (response.body === null) throw new Error('missing body');
        const reader = response.body.getReader();
        await reader.read();
        verifyingStream = client.verifyResponse(
          'stream',
          callerSignal ? { signal: new AbortController().signal } : undefined,
        );
        if (eviction === 'replacement') {
          client.response = () =>
            Response.json({ id: 'stream', text: 'x'.repeat(150) });
          await (await client.send()).json();
        }
        finish();
        while (!(await reader.read()).done) {
          /* Drain to apply receipt retention. */
        }
        if (eviction === 'replacement') {
          await expect(client.verifyResponse('stream')).rejects.toMatchObject({
            failure: { code: 'api.completion_not_found' },
          });
        }
        releases[0]();
        if (first !== undefined) {
          await expect(verifyingFirst).resolves.toBe(first.id);
        }

        client.response = jsonResponse;
        const third = await (await client.send()).json();
        await expect(client.verifyResponse(third.id)).rejects.toMatchObject({
          failure: { code: 'api.completion_not_found' },
        });
        releases[1]();
        await expect(verifyingStream).resolves.toBe('stream');
        const fourth = await (await client.send()).json();
        await expect(client.verifyResponse(fourth.id)).resolves.toBe(fourth.id);
      } finally {
        finish();
        for (const release of releases) release();
        await Promise.all([verifyingFirst, verifyingStream]);
      }
    },
  );

  test('rejects an unretainable request before any preflight', async () => {
    const client = new Client({ maxBodyBytes: 1024, maxReceiptCacheBytes: 10 });
    await expect(client.send()).rejects.toMatchObject({
      failure: { code: 'api.body_too_large' },
    });
    expect(client.verified).toEqual([]);
  });

  describe.each(['ed25519', 'ecdsa'] as const)(
    '%s encrypted request bounds',
    (signingAlgo) => {
      test.each(['maxBodyBytes', 'maxReceiptCacheBytes'] as const)(
        'checks %s against the wire body before preflight',
        async (limitName) => {
          const body = JSON.stringify({
            model: 'm',
            messages: [{ role: 'user', content: '雪'.repeat(200) }],
          });
          const pair = createE2eeClientKeyPair(signingAlgo);
          const prepared = await prepareE2eeChatRequest({
            request: new Request('https://example.test/v1/chat/completions', {
              method: 'POST',
              body,
            }),
            modelKey: { signingAlgo, publicKey: pair.publicKey },
          });
          const wireSize = (await prepared.request.arrayBuffer()).byteLength;
          expect(new TextEncoder().encode(body).byteLength).toBeLessThan(
            wireSize - 1,
          );
          for (const limit of [wireSize - 1, wireSize]) {
            const client = new Client({
              e2ee: true,
              signingAlgo,
              [limitName]: limit,
            });
            await expect(
              client.fetch('https://example.test/v1/chat/completions', {
                method: 'POST',
                body,
              }),
            ).rejects.toMatchObject({
              failure: {
                code:
                  limit < wireSize
                    ? 'api.body_too_large'
                    : 'policy.model_attestation_required',
              },
            });
            // The fake session deliberately has no key; reaching that error shows
            // exact-boundary requests passed sizing and invoked preflight.
            expect(client.verified).toEqual(limit < wireSize ? [] : ['m']);
          }
        },
      );

      test('ignores the receipt budget when retention is disabled', async () => {
        const client = new Client({
          e2ee: true,
          signingAlgo,
          maxReceiptCacheBytes: 1,
          responseCacheTimeToLiveMs: 0,
        });
        await expect(client.send()).rejects.toMatchObject({
          failure: { code: 'policy.model_attestation_required' },
        });
        expect(client.verified).toEqual(['m']);
      });

      test('budgets formatted JSON by its transformed wire size while bounding input', async () => {
        const body = `${' '.repeat(200)}{"model": "m"}\n`;
        const inputSize = new TextEncoder().encode(body).byteLength;
        const pair = createE2eeClientKeyPair(signingAlgo);
        const prepared = await prepareE2eeChatRequest({
          request: new Request('https://example.test/v1/chat/completions', {
            method: 'POST',
            body,
          }),
          modelKey: { signingAlgo, publicKey: pair.publicKey },
        });
        const wireSize = (await prepared.request.arrayBuffer()).byteLength;
        expect(wireSize).toBeLessThan(inputSize);
        for (const [maxBodyBytes, maxReceiptCacheBytes, admitted] of [
          [inputSize, wireSize, true],
          [inputSize, wireSize - 1, false],
          [inputSize - 1, wireSize, false],
        ] as const) {
          const client = new Client({
            e2ee: true,
            signingAlgo,
            maxBodyBytes,
            maxReceiptCacheBytes,
          });
          await expect(
            client.fetch('https://example.test/v1/chat/completions', {
              method: 'POST',
              body,
            }),
          ).rejects.toMatchObject({
            failure: {
              code: admitted
                ? 'policy.model_attestation_required'
                : 'api.body_too_large',
            },
          });
          expect(client.verified).toEqual(admitted ? ['m'] : []);
        }
        const responseBody = JSON.stringify({ id: 'formatted' });
        const client = new Client({
          e2ee: true,
          signingAlgo,
          maxBodyBytes: inputSize,
          maxReceiptCacheBytes:
            wireSize + new TextEncoder().encode(responseBody).byteLength,
        });
        client.modelKey = { signingAlgo, publicKey: pair.publicKey };
        client.response = () =>
          new Response(responseBody, {
            headers: { 'content-type': 'application/json' },
          });
        const response = await client.fetch(
          'https://example.test/v1/chat/completions',
          { method: 'POST', body },
        );
        expect(await response.json()).toEqual({ id: 'formatted' });
        await expect(client.verifyResponse('formatted')).resolves.toBe(
          'formatted',
        );
      });
    },
  );

  test('disabled receipt retention does not limit a plaintext request', async () => {
    const client = new Client({
      maxReceiptCacheBytes: 1,
      responseCacheTimeToLiveMs: 0,
    });
    expect((await client.send()).ok).toBe(true);
    expect(client.verified).toEqual(['m']);
  });

  test.each([400, 429, 500])(
    'bounds HTTP %i error bodies independently of the receipt budget',
    async (status) => {
      const client = new Client({
        maxBodyBytes: 100,
        maxReceiptCacheBytes: 30,
      });
      client.response = () => new Response('e'.repeat(80), { status });
      const response = await client.send();
      expect(response.status).toBe(status);
      expect(await response.text()).toBe('e'.repeat(80));
      client.response = () => new Response('e'.repeat(101), { status });
      await expect((await client.send()).text()).rejects.toMatchObject({
        failure: { code: 'api.body_too_large' },
      });
    },
  );

  test('bounds signed SSE tail draining after the consumer stops at DONE', async () => {
    const client = new Client({ maxBodyBytes: 90 });
    let tail: (() => void) | undefined;
    client.response = () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(
              new TextEncoder().encode(
                'data: {"id":"stream"}\n\ndata: [DONE]\n\n',
              ),
            );
            tail = () => {
              controller.enqueue(
                new TextEncoder().encode(`: ${'x'.repeat(100)}\n\n`),
              );
              controller.close();
            };
          },
        }),
        { headers: { 'content-type': 'text/event-stream' } },
      );
    const response = await client.send();
    if (response.body === null) throw new Error('missing body');
    const reader = response.body.getReader();
    await reader.read();
    const check = expect(client.verifyResponse('stream')).rejects.toMatchObject(
      { failure: { code: 'api.body_too_large' } },
    );
    const cancelled = reader.cancel();
    tail?.();
    await cancelled;
    await check;
  });

  test('shares same-key pending work and rejects additional preflights at capacity', async () => {
    const client = new Client({ maxCacheEntries: 1 });
    let release: (() => void) | undefined;
    client.gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const one = client.verify('one');
    const shared = client.verify('one');
    await expect(client.verify('two')).rejects.toMatchObject({
      failure: { code: 'api.invalid_input' },
    });
    release?.();
    expect(await Promise.all([one, shared])).toEqual(['one', 'one']);
    expect(client.verified).toEqual(['one']);
  });
});
