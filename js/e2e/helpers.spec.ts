import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ApiError, VerificationError } from '../dist/node.js';
import { retryReceipt, selectedModels } from './helpers.ts';

const unavailable = () =>
  new ApiError({
    code: 'api.completion_signature_unavailable',
    details: { providerErrorCode: 'not_ready', providerMessage: 'not ready' },
  });

test('receipt propagation recovers without replaying inference', async () => {
  let lookups = 0;
  const waits: number[] = [];
  const result = await retryReceipt(
    async () => {
      if (++lookups < 3) throw unavailable();
      return 'verified';
    },
    async (ms) => {
      waits.push(ms);
    },
  );
  assert.equal(result, 'verified');
  assert.equal(lookups, 3);
  assert.deepEqual(waits, [500, 1000]);
});

test('an unavailable receipt stops after five lookups', async () => {
  let lookups = 0;
  const waits: number[] = [];
  await assert.rejects(
    retryReceipt(
      async () => {
        lookups++;
        throw unavailable();
      },
      async (ms) => {
        waits.push(ms);
      },
    ),
    unavailable().constructor,
  );
  assert.equal(lookups, 5);
  assert.deepEqual(waits, [500, 1000, 2000, 4000]);
});

test('verification failures are not retried', async () => {
  let lookups = 0;
  const error = new VerificationError({
    code: 'signature.payload_mismatch',
    details: { source: 'signed_payload', reason: 'text_mismatch' },
  });
  await assert.rejects(
    retryReceipt(
      async () => {
        lookups++;
        throw error;
      },
      async () => {
        assert.fail('must not back off');
      },
    ),
    (caught) => caught === error,
  );
  assert.equal(lookups, 1);
});

test('a test deadline prevents receipt lookup and cancels propagation backoff', async () => {
  const reason = new Error('deadline');
  let calls = 0;
  await assert.rejects(
    retryReceipt(async () => {
      calls++;
      return 'unused';
    }, AbortSignal.abort(reason)),
    (error) => error === reason,
  );
  assert.equal(calls, 0);
  const controller = new AbortController();
  await assert.rejects(
    retryReceipt(async () => {
      calls++;
      queueMicrotask(() => controller.abort(reason));
      throw unavailable();
    }, controller.signal),
    { name: 'AbortError' },
  );
  assert.equal(calls, 1);
});

test('routes mixed model selections by endpoint', (t) => {
  const chat = { id: 'external/chat', provider: 'external', endpoint: 'chat' };
  const decision = {
    id: 'typesafe/jev',
    provider: 'external',
    endpoint: 'systemone',
  };
  const previous = process.env.NEARAI_E2E_MODELS;
  t.after(() => {
    if (previous === undefined) delete process.env.NEARAI_E2E_MODELS;
    else process.env.NEARAI_E2E_MODELS = previous;
  });
  process.env.NEARAI_E2E_MODELS = JSON.stringify([decision, chat]);

  assert.deepEqual(selectedModels('chat'), [chat]);
  assert.deepEqual(selectedModels('systemone'), [decision]);
});
