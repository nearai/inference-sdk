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
      transport: {
        fetch: async () =>
          this.response?.() ??
          Response.json({ id: `id-${++this.next}`, text: 'answer' }),
        fetchCompletionSignature: async () => ({
          kind: 'gateway',
          signedText: '',
          signature: '',
          signer: { signingAlgo: 'ed25519', signingAddress: '00'.repeat(32) },
        }),
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
