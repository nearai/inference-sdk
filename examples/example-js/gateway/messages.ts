import { setTimeout as sleep } from 'node:timers/promises';
import { InferenceClient, isApiError } from '@nearai/inference-sdk/node';

const BASE_URL = 'https://cloud-api.near.ai/v1/';
const MODEL = 'anthropic/claude-haiku-4-5';
const SIGNING_ALGO = 'ed25519';

async function main(): Promise<void> {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('NEARAI_API_KEY is required');

  const inferenceClient = new InferenceClient({
    apiKey,
    baseUrl: BASE_URL,
    signingAlgo: SIGNING_ALGO,
  });

  await runNonStreamingExample(inferenceClient);
  await runStreamingExample(inferenceClient);
}

async function runNonStreamingExample(
  inferenceClient: InferenceClient,
): Promise<void> {
  const response = await inferenceClient.messages.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_tokens: 128,
  });
  const verified = await verifyReceipt(inferenceClient, response.id);
  console.log({ id: response.id, verified, output: response.content });
}

async function runStreamingExample(
  inferenceClient: InferenceClient,
): Promise<void> {
  const stream = await inferenceClient.messages.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_tokens: 128,
    stream: true,
  });

  let responseId: string | undefined;
  // Streamed text is provisional until the complete response is verified.
  for await (const event of stream) {
    if (event.type === 'message_start') responseId = event.message.id;
    if (
      event.type === 'content_block_delta' &&
      event.delta.type === 'text_delta'
    )
      process.stdout.write(event.delta.text);
  }

  if (responseId === undefined)
    throw new Error('Stream returned no response ID');
  console.log('\nReceipt status:', {
    id: responseId,
    verified: await verifyReceipt(inferenceClient, responseId),
  });
}

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

await main();
