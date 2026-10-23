import { InferenceClient } from '@nearai/inference-sdk/node';
import { TypeSafeClient } from '@typesafe-ai/sdk';

/** Keep the verified transport and official SDK configuration together. */
export function createVerifiedJevClients(
  options: ConstructorParameters<typeof InferenceClient>[0],
) {
  if (options.e2ee || options.ohttp) {
    throw new Error('Jev requires e2ee and ohttp disabled.');
  }
  const inference = new InferenceClient({ ...options, e2ee: false, ohttp: false });
  const baseUrl = new URL(inference.getBaseUrl());
  if (!baseUrl.pathname.endsWith('/v1/')) {
    throw new Error('The Jev example requires a NEAR base URL ending in /v1/.');
  }
  const jev = new TypeSafeClient({
    apiKey: options.apiKey ?? 'verified-transport',
    baseURL: new URL('../', baseUrl).toString(),
    fetch: inference.fetch,
    compression: false,
    retry: { maxRetries: 0 },
    timeout: 60_000,
  });
  return { inference, jev };
}

export function receiptId(response: Response): string {
  const id = response.headers.get('x-generation-id');
  if (!id) throw new Error('Missing System One receipt ID.');
  return id;
}
