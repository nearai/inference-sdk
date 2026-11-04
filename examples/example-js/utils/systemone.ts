import { InferenceClient } from '@nearai/inference-sdk/node';
import { TypeSafeClient } from '@typesafe-ai/sdk';

/** Keep the verified transport and TypeSafe SDK configuration together. */
export function createVerifiedSystemOneClients(
  options: ConstructorParameters<typeof InferenceClient>[0] = {},
) {
  if (options.e2ee || options.ohttp) {
    throw new Error('System One requires e2ee and ohttp disabled.');
  }
  const inference = new InferenceClient({
    ...options,
    e2ee: false,
    ohttp: false,
  });
  const baseUrl = new URL(inference.getBaseUrl());
  if (!baseUrl.pathname.endsWith('/v1/')) {
    throw new Error(
      'The System One example requires a NEAR base URL ending in /v1/.',
    );
  }
  const typesafe = new TypeSafeClient({
    apiKey: options.apiKey ?? 'verified-transport',
    baseURL: new URL('../', baseUrl).toString(),
    fetch: inference.fetch,
    compression: false,
    retry: { maxRetries: 0 },
    timeout: 120_000,
  });
  return { inference, typesafe };
}

export function receiptId(response: Response): string {
  const id = response.headers.get('x-generation-id');
  if (!id) throw new Error('Missing System One receipt ID.');
  return id;
}
