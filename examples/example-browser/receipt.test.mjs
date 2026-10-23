import assert from 'node:assert/strict';
import test from 'node:test';
import { ApiError } from '@nearai/inference-sdk';
import { isRetryableSignatureLookup } from './receipt.ts';

for (const [providerErrorCode, retryable] of [['not_found', true], ['SIGNATURE_UNSUPPORTED', false]]) {
  test(`receipt availability: ${providerErrorCode}`, () => {
    const error = new ApiError({
      code: 'api.completion_signature_unavailable',
      details: { providerErrorCode, providerMessage: 'Receipt unavailable' },
    });
    assert.equal(isRetryableSignatureLookup(error), retryable);
  });
}

test('transient signature lookup failures remain retryable', () => {
  const error = new ApiError({
    code: 'api.http_status',
    details: { resource: 'completion_signature', status: 503 },
    retryable: true,
  });
  assert.equal(isRetryableSignatureLookup(error), true);
});

test('expired receipts and other failures cannot be retried', () => {
  assert.equal(isRetryableSignatureLookup(new ApiError({ code: 'api.completion_not_found' })), false);
  assert.equal(isRetryableSignatureLookup(new Error('Verification failed')), false);
});
