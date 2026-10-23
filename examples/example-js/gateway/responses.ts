import { setTimeout as sleep } from 'node:timers/promises';
import { InferenceClient, isApiError } from '@nearai/inference-sdk/node';

// Retry receipt lookup for up to ten seconds, keeping the original inference.
async function verifyReceipt(
  client: InferenceClient,
  id: string,
): Promise<boolean> {
  const deadline = Date.now() + 10_000;
  let backoff = 500;
  while (Date.now() < deadline) {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        client.verifyResponse(id).then(() => true),
        new Promise<false>((resolve) => {
          timer = setTimeout(() => resolve(false), deadline - Date.now());
        }),
      ]);
    } catch (error) {
      if (
        !isApiError(error) ||
        (!error.retryable &&
          error.failure.code !== 'api.completion_signature_unavailable')
      )
        throw error;
    } finally {
      clearTimeout(timer);
    }
    await sleep(Math.min(backoff, Math.max(0, deadline - Date.now())));
    backoff = Math.min(backoff * 2, 2_000);
  }
  return false;
}

const apiKey = process.env.NEARAI_API_KEY;
if (!apiKey) throw new Error('NEARAI_API_KEY is required');
const client = new InferenceClient({ apiKey });
const request = {
  model: 'z-ai/glm-5.3-flash',
  input: 'Reply with the word ok.',
  store: false,
};
const response = await client.responses.create(request);
const verified = await verifyReceipt(client, response.id);
console.log({ id: response.id, verified, output: response.output_text });

const stream = await client.responses.create({ ...request, stream: true });
let responseId: string | undefined;
for await (const event of stream) {
  if (event.type === 'response.created') responseId = event.response.id;
  if (event.type === 'response.output_text.delta')
    process.stdout.write(event.delta);
}
if (responseId === undefined) throw new Error('Stream returned no response ID');
// Streamed text is provisional until the complete response is verified.
console.log('\nReceipt status:', {
  id: responseId,
  verified: await verifyReceipt(client, responseId),
});
