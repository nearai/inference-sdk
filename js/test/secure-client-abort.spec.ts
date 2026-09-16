import { SecureClient } from '../src';

const baseUrl = 'https://gateway.test/v1/';

afterEach(() => {
  jest.restoreAllMocks();
});

test('rejects an already aborted request with the caller’s reason', async () => {
  const fetch = jest.spyOn(globalThis, 'fetch');
  const client = new SecureClient({ apiKey: 'test-key', baseUrl });
  const reason = new Error('Chat cancelled');

  const response = client.fetch(`${baseUrl}chat/completions`, {
    method: 'POST',
    body: '{}',
    signal: AbortSignal.abort(reason),
  });

  await expect(response).rejects.toBe(reason);
  expect(fetch).not.toHaveBeenCalled();
});

test('aborts while a streamed request body is stalled before any network request', async () => {
  const fetch = jest.spyOn(globalThis, 'fetch');
  const client = new SecureClient({ apiKey: 'test-key', baseUrl });
  const controller = new AbortController();
  const body = new TransformStream<Uint8Array>();
  const writer = body.writable.getWriter();
  const options = {
    method: 'POST',
    body: body.readable,
    duplex: 'half',
    signal: controller.signal,
  };
  const request = new Request(`${baseUrl}chat/completions`, options);
  const reason = new Error('Chat cancelled during upload');

  const response = client.fetch(request);
  await writer.write(new TextEncoder().encode('{"model":'));
  controller.abort(reason);

  try {
    await expect(response).rejects.toBe(reason);
    expect(fetch).not.toHaveBeenCalled();
  } finally {
    await writer.close();
  }
});

test('still reports malformed request JSON as an API input error', async () => {
  const fetch = jest.spyOn(globalThis, 'fetch');
  const client = new SecureClient({ apiKey: 'test-key', baseUrl });

  const response = client.fetch(`${baseUrl}chat/completions`, {
    method: 'POST',
    body: '{invalid json',
  });

  await expect(response).rejects.toMatchObject({
    failure: {
      code: 'api.invalid_input',
      details: { field: 'request body', reason: 'invalid_json' },
    },
  });
  expect(fetch).not.toHaveBeenCalled();
});
