// Compile-only tests for the public error discriminants.
import type { ApiFailure } from '../src';

declare const failure: ApiFailure;
if (failure.code === 'api.transport_failed') {
  const retryable: true = failure.retryable;
  void retryable;
}
if (failure.code === 'api.inference_transport_failed') {
  const retryable: false = failure.retryable;
  void retryable;
}
