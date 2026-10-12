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
export async function retryReceipt<T>(lookup: () => Promise<T>): Promise<T> {
  for (const backoffMs of [500, 1_000, 2_000, 4_000]) {
    try {
      return await lookup();
    } catch (error) {
      if (
        !(isApiError(error) || isGenericApiError(error)) ||
        !error.retryable
      ) {
        throw error;
      }
    }
    await delay(backoffMs);
  }
  return lookup();
}
