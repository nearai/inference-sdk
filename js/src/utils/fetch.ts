export async function fetchTimeout(
  input: string | URL | Request,
  timeout: number,
  init?: Omit<RequestInit, 'signal'>,
): Promise<Response> {
  let controller;
  let timeoutId;

  if (timeout) {
    controller = new AbortController();
    timeoutId = setTimeout(() => controller!.abort(), timeout);
  }

  try {
    return await fetch(input, {
      ...init,
      signal: controller?.signal,
    });
  } catch (e: unknown) {
    if (controller?.signal.aborted) {
      throw new Error(`Fetch url ${input} timeout`);
    }
    throw e;
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  }
}
