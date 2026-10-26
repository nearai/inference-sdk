// Compile-only tests for the public error discriminants.
import type { ApiFailure } from '../src';

declare const failure: ApiFailure;
if (failure.code === 'api.transport_failed') {
  const retryable: boolean = failure.retryable;
  void retryable;
}
