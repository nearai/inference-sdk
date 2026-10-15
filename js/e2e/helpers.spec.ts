import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ApiError, VerificationError } from '../dist/node.js';
import { retryReceipt } from './helpers.ts';

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
