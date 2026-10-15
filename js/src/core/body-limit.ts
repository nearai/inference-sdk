import { ApiError } from '../utils/errors';

export function requireBodySize(size: number, limit: number): void {
  if (size > limit) throw new ApiError({ code: 'api.body_too_large' });
}

/** Read with a bound even when Content-Length is absent or misleading. */
export async function readBoundedBody(
  body: ReadableStream<Uint8Array> | null,
  limit: number,
  signal?: AbortSignal,
): Promise<Uint8Array<ArrayBuffer>> {
  signal?.throwIfAborted();
  if (body === null) return new Uint8Array();
  const reader = body.getReader();
  const abort = (): void => {
    void reader.cancel(signal?.reason).catch(() => undefined);
  };
  signal?.addEventListener('abort', abort, { once: true });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      signal?.throwIfAborted();
      if (next.done) break;
      requireBodySize(size + next.value.byteLength, limit);
      size += next.value.byteLength;
      chunks.push(next.value);
    }
  } catch (cause) {
    void reader.cancel(cause).catch(() => undefined);
    throw cause;
  } finally {
    signal?.removeEventListener('abort', abort);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
