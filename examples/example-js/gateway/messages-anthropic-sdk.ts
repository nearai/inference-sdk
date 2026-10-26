import Anthropic from '@anthropic-ai/sdk';
import { InferenceClient, type SigningAlgo } from '@nearai/inference-sdk/node';
import { transportOptions } from '../transport-options.ts';

const BASE_URL = process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1/';
const MODEL = process.env.NEARAI_MODEL ?? 'anthropic/claude-haiku-4-5';
const SIGNING_ALGO = (process.env.NEARAI_SIGNING_ALGO ??
  'ed25519') as SigningAlgo;
const signal = AbortSignal.timeout(120_000);

async function main(): Promise<void> {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('NEARAI_API_KEY is required');
  const inferenceClient = new InferenceClient({
    apiKey,
    baseUrl: BASE_URL,
    ...transportOptions(SIGNING_ALGO),
  });
  const api = new Anthropic({
    apiKey,
    baseURL: inferenceClient.getBaseUrl().replace(/v1\/$/, ''),
    fetch: inferenceClient.fetch,
    maxRetries: 0,
  });
  await runNonStreamingExample(api, inferenceClient);
  await runStreamingExample(api, inferenceClient);
}

async function runNonStreamingExample(
  api: Anthropic,
  inferenceClient: InferenceClient,
): Promise<void> {
  const response = await api.messages.create(
    {
      model: MODEL,
      messages: [{ role: 'user', content: 'Reply with the word ok.' }],
      max_tokens: 128,
    },
    { signal },
  );
  const verified = await inferenceClient.verifyResponse(response.id);
  console.log(`Verified ${verified.signatureKind} response.`);
  console.log(
    response.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join(''),
  );
}

async function runStreamingExample(
  api: Anthropic,
  inferenceClient: InferenceClient,
): Promise<void> {
  const stream = await api.messages.create(
    {
      model: MODEL,
      messages: [{ role: 'user', content: 'Reply with the word ok.' }],
      max_tokens: 128,
      stream: true,
    },
    { signal },
  );
  let id: string | undefined;
  // Stream text as it arrives; verify the receipt after full consumption.
  for await (const event of stream) {
    if (event.type === 'message_start') id = event.message.id;
    if (
      event.type === 'content_block_delta' &&
      event.delta.type === 'text_delta'
    )
      process.stdout.write(event.delta.text);
  }
  process.stdout.write('\n');
  if (id === undefined) throw new Error('Stream returned no response ID');
  const verified = await inferenceClient.verifyResponse(id);
  console.log(`Verified ${verified.signatureKind} streaming response.`);
}

await main();
