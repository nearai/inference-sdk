import { ApiError } from '../utils/errors';

export function requireBodySize(size: number, limit: number): void {
  if (size > limit) throw new ApiError({ code: 'api.body_too_large' });
}

/** Coalesce fragments so retained memory does not grow with the chunk count. */
export class BoundedBodyBuffer {
  private buffer: Uint8Array<ArrayBuffer> = new Uint8Array();
  private size = 0;

  constructor(private readonly limit: number) {}

  append(chunk: Uint8Array): void {
    const required = this.size + chunk.byteLength;
    requireBodySize(required, this.limit);
    if (required > this.buffer.byteLength) {
      const capacity = Math.min(
        this.limit,
        Math.max(required, this.buffer.byteLength * 2, 1024),
      );
      const next = new Uint8Array(capacity);
      next.set(this.view());
      this.buffer = next;
    }
    this.buffer.set(chunk, this.size);
    this.size = required;
  }

  view(): Uint8Array<ArrayBuffer> {
    return this.buffer.subarray(0, this.size);
  }

  take(): Uint8Array<ArrayBuffer> {
    const bytes = this.buffer.slice(0, this.size);
    this.clear();
    return bytes;
  }

  clear(): void {
    this.buffer = new Uint8Array();
    this.size = 0;
  }
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
  const buffer = new BoundedBodyBuffer(limit);
  try {
    while (true) {
      const next = await reader.read();
      signal?.throwIfAborted();
      if (next.done) break;
      buffer.append(next.value);
    }
  } catch (cause) {
    void reader.cancel(cause).catch(() => undefined);
    throw cause;
  } finally {
    signal?.removeEventListener('abort', abort);
    reader.releaseLock();
  }
  return buffer.take();
}
