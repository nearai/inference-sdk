import { readBoundedBody } from '../src/core/body-limit';

test('coalesces many small fragments and preserves their bytes', async () => {
  let index = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index === 100_000) {
        controller.close();
      } else {
        controller.enqueue(new Uint8Array([index % 256, 255]));
        index++;
      }
    },
  });
  const body = await readBoundedBody(stream, 200_000);
  expect(body.byteLength).toBe(200_000);
  for (let i = 0; i < 100_000; i++) {
    if (body[2 * i] !== i % 256 || body[2 * i + 1] !== 255) {
      throw new Error(`fragment ${i} changed`);
    }
  }
});

test('cancels at the first fragment exceeding the byte limit', async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new Uint8Array(2));
    },
    cancel() {
      cancelled = true;
    },
  });
  await expect(readBoundedBody(stream, 5)).rejects.toMatchObject({
    failure: { code: 'api.body_too_large' },
  });
  expect(cancelled).toBe(true);
});
