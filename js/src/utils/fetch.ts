export async function fetchTimeout(
  input: string | URL | Request,
  timeout: number,
  init?: Omit<RequestInit, 'signal'>,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    return await fetch(input, {
      ...init,
      signal: controller.signal,
    });
  } catch (e: unknown) {
    if (controller.signal.aborted) {
      throw new Error(`Fetch url ${input} timeout`);
    }
    throw e;
  } finally {
    clearTimeout(timeoutId);
  }
}
