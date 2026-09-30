import { setTimeout as delay } from 'node:timers/promises';
import { RateLimitError } from 'openai';

// Retry only rejected Chat requests, before consuming any successful response.
export async function retryRateLimit<T>(send: () => Promise<T>): Promise<T> {
  for (const backoffSeconds of [5, 10, 20]) {
    let retryAfter: string | null | undefined;
    try {
      const response = await send();
      if (!(response instanceof Response) || response.status !== 429) {
        return response;
      }
      retryAfter = response.headers.get('retry-after');
      await response.body?.cancel();
    } catch (error) {
      if (!(error instanceof RateLimitError)) throw error;
      retryAfter = error.headers?.get('retry-after');
    }
    const seconds = retryAfter?.trim();
    const requestedDelay =
      seconds && /^\d+$/.test(seconds) ? Number(seconds) : 0;
    const waitSeconds = Math.max(
      backoffSeconds,
      Number.isFinite(requestedDelay) ? requestedDelay : 0,
    );
    console.warn(`Chat returned HTTP 429; retrying in ${waitSeconds}s`);
    await delay(waitSeconds * 1_000);
  }
  return send();
}
