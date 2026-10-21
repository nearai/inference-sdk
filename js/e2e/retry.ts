import timers from 'node:timers/promises';
import { APIConnectionError, RateLimitError } from 'openai';
import { isApiError as isGenericApiError } from '../dist/index.js';
import { isApiError } from '../dist/node.js';

// Retry only rejected Chat requests, before consuming any successful response.
export async function retryRateLimit<T>(
  send: () => Promise<T>,
  signal: AbortSignal,
  wait: (milliseconds: number, signal: AbortSignal) => Promise<unknown> = (
    milliseconds,
    signal,
  ) => timers.setTimeout(milliseconds, undefined, { signal }),
): Promise<T> {
  for (const backoffSeconds of [5, 10, 20]) {
    signal.throwIfAborted();
    let retryAfter: string | null | undefined;
    try {
      const response = await send();
      if (!(response instanceof Response) || response.status !== 429) {
        return response;
      }
      retryAfter = response.headers.get('retry-after');
      await response.body?.cancel();
    } catch (error) {
      const cause = error instanceof APIConnectionError ? error.cause : error;
      if (error instanceof RateLimitError) {
        retryAfter = error.headers?.get('retry-after');
      } else if (
        (isApiError(cause) || isGenericApiError(cause)) &&
        cause.failure.code === 'api.http_status' &&
        cause.failure.details.resource === 'ohttp' &&
        cause.failure.details.status === 429
      ) {
        retryAfter = cause.failure.details.retryAfter;
      } else {
        throw error;
      }
    }
    const seconds = retryAfter?.trim();
    const requestedDelay =
      seconds && /^\d+$/.test(seconds)
        ? Number(seconds)
        : (Date.parse(retryAfter ?? '') - Date.now()) / 1_000;
    const waitSeconds = Math.max(
      backoffSeconds,
      Number.isNaN(requestedDelay) ? 0 : requestedDelay,
    );
    console.warn(`Chat returned HTTP 429; retrying in ${waitSeconds}s`);
    // Node turns a timeout above the signed 32-bit limit into a 1 ms timer.
    // Long Retry-After values must remain abortable without overflowing it.
    let remainingMs = Math.min(waitSeconds * 1_000, Number.MAX_SAFE_INTEGER);
    while (remainingMs > 0) {
      signal.throwIfAborted();
      const chunkMs = Math.min(remainingMs, 2_147_483_647);
      await wait(chunkMs, signal);
      remainingMs -= chunkMs;
    }
  }
  signal.throwIfAborted();
  return send();
}
