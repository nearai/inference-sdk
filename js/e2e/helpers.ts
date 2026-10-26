import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { isApiError as isGenericApiError } from '../dist/index.js';
import { isApiError } from '../dist/node.js';

export function requiredEnv(name: string): string {
  const value = process.env[name];
  assert.ok(value, `${name} is required for live E2E tests`);
  return value;
}

// Allow receipt propagation without repeating inference or retrying
// cryptographic failures. Each live test still has an overall deadline.
export async function retryReceipt<T>(
  lookup: () => Promise<T>,
  waitOrSignal:
    | ((milliseconds: number) => Promise<unknown>)
    | AbortSignal = delay,
): Promise<T> {
  const signal = typeof waitOrSignal === 'function' ? undefined : waitOrSignal;
  const wait =
    typeof waitOrSignal === 'function'
      ? waitOrSignal
      : (ms: number) => delay(ms, undefined, { signal });
  for (const backoffMs of [500, 1_000, 2_000, 4_000]) {
    signal?.throwIfAborted();
    try {
      return await lookup();
    } catch (error) {
      if (
        !(isApiError(error) || isGenericApiError(error)) ||
        (!error.retryable &&
          error.failure.code !== 'api.completion_signature_unavailable')
      ) {
        throw error;
      }
    }
    await wait(backoffMs);
  }
  signal?.throwIfAborted();
  return lookup();
}

export function selectedModels(
  endpoint: 'chat' | 'systemone' | 'responses' | 'messages',
): {
  id: string;
  provider: 'near' | 'chutes' | 'external';
  endpoint: 'chat' | 'systemone' | 'responses' | 'messages';
}[] {
  const models = JSON.parse(requiredEnv('NEARAI_E2E_MODELS'));
  return models.filter(
    (model: { endpoint: string }) => model.endpoint === endpoint,
  );
}
