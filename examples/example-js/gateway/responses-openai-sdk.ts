import { InferenceClient, type SigningAlgo } from '@nearai/inference-sdk/node';
import OpenAI from 'openai';
import { transportOptions } from '../transport-options.ts';

const BASE_URL = process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1/';
const MODEL = process.env.NEARAI_MODEL ?? 'z-ai/glm-5.3-flash';
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
  const api = new OpenAI({
    apiKey,
    baseURL: inferenceClient.getBaseUrl(),
    fetch: inferenceClient.fetch,
    maxRetries: 0,
  });
  await runNonStreamingExample(api, inferenceClient);
  await runStreamingExample(api, inferenceClient);
}

async function runNonStreamingExample(
  api: OpenAI,
  inferenceClient: InferenceClient,
): Promise<void> {
  const response = await api.responses.create(
    {
      model: MODEL,
      input: 'Reply with the word ok.',
      max_output_tokens: 1024,
      store: false,
    },
    { signal },
  );
  const verified = await inferenceClient.verifyResponse(response.id);
  console.log(`Verified ${verified.signatureKind} response.`);
  console.log(response.output_text);
}

async function runStreamingExample(
  api: OpenAI,
  inferenceClient: InferenceClient,
): Promise<void> {
  const stream = await api.responses.create(
    {
      model: MODEL,
      input: 'Reply with the word ok.',
      max_output_tokens: 1024,
      store: false,
      stream: true,
    },
    { signal },
  );
  let id: string | undefined;
  // Stream text as it arrives; verify the receipt after full consumption.
  for await (const event of stream) {
    if (event.type === 'response.created') id = event.response.id;
    if (event.type === 'response.output_text.delta')
      process.stdout.write(event.delta);
  }
  process.stdout.write('\n');
  if (id === undefined) throw new Error('Stream returned no response ID');
  const verified = await inferenceClient.verifyResponse(id);
  console.log(`Verified ${verified.signatureKind} streaming response.`);
}

await main();
