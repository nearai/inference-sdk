import { isApiError } from '@nearai/inference-sdk';

export function isRetryableSignatureLookup(error: unknown): boolean {
  return isApiError(error) && (
    error.retryable || (
      error.failure.code === 'api.completion_signature_unavailable' &&
      error.failure.details.providerErrorCode === 'not_found'
    )
  );
}
