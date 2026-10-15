import assert from 'node:assert/strict';
import { test } from 'node:test';
import { APIConnectionError } from 'openai';
import { ApiError as GenericApiError } from '../dist/index.js';
import { ApiError } from '../dist/node.js';
import { retryRateLimit } from './retry.ts';

for (const [name, ErrorType] of [
  ['Node', ApiError],
  ['generic', GenericApiError],
] as const) {
  test(`retries wrapped ${name} OHTTP rate limits after Retry-After`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
    const cause = new ErrorType({
      code: 'api.http_status',
      details: { resource: 'ohttp', status: 429, retryAfter: '12' },
      retryable: true,
    });
    let attempts = 0;
    const result = retryRateLimit(async () => {
      attempts++;
      if (attempts === 1) throw new APIConnectionError({ cause });
      return 'ok';
    }, t.signal);
    await Promise.resolve();
    t.mock.timers.tick(11_999);
    assert.equal(attempts, 1);
    t.mock.timers.tick(1);
    assert.equal(await result, 'ok');
    assert.equal(attempts, 2);
  });
}

test('does not retry an OHTTP server error', async (t) => {
  const cause = new ApiError({
    code: 'api.http_status',
    details: { resource: 'ohttp', status: 503 },
    retryable: true,
  });
  const error = new APIConnectionError({ cause });
  let attempts = 0;
  await assert.rejects(
    retryRateLimit(async () => {
      attempts++;
      throw error;
    }, t.signal),
    (thrown) => thrown === error,
  );
  assert.equal(attempts, 1);
});

test('cancels a long Retry-After wait when the test deadline expires', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const controller = new AbortController();
  let attempts = 0;
  const result = retryRateLimit(async () => {
    attempts++;
    return new Response(null, {
      status: 429,
      headers: { 'Retry-After': '300' },
    });
  }, controller.signal);
  await Promise.resolve();
  await Promise.resolve();
  controller.abort();
  await assert.rejects(result, { name: 'AbortError' });
  t.mock.timers.tick(300_000);
  assert.equal(attempts, 1);
});

test('persistent 429 stops after four requests and a successful response is never replayed', async (t) => {
  for (const statuses of [[429, 429, 429, 429], [429, 200], [503], [200]]) {
    let calls = 0;
    const waits: number[] = [];
    const result = await retryRateLimit(
      async () => new Response(null, { status: statuses[calls++] }),
      t.signal,
      async (ms) => {
        waits.push(ms);
      },
    );
    assert.equal(calls, statuses.length);
    assert.equal(result.status, statuses.at(-1));
    assert.deepEqual(waits, [5000, 10000, 20000].slice(0, statuses.length - 1));
  }
});
