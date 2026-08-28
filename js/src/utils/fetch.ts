/** Internal timeout marker for adapters that need a stable retry policy. */
export class FetchTimeoutError extends Error {
  readonly name = 'FetchTimeoutError';

  constructor(cause?: unknown) {
    super('Fetch timed out', { cause });
  }
}

type FetchTimeoutParams = {
  input: string | URL | Request;
  timeout: number;
  init?: Omit<RequestInit, 'signal'>;
};

export async function fetchTimeout({
  input,
  timeout,
  init,
}: FetchTimeoutParams): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    return await fetch(input, {
      ...init,
      signal: controller.signal,
    });
  } catch (cause: unknown) {
    if (controller.signal.aborted) {
      throw new FetchTimeoutError(cause);
    }
    throw cause;
  } finally {
    clearTimeout(timeoutId);
  }
}
