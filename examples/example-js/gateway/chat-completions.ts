import { InferenceClient } from '@nearai/inference-sdk/node';
import { transportOptions } from '../utils/transport-options.ts';

const API_KEY = process.env.NEARAI_API_KEY;
const BASE_URL = process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1/';
const MODEL = process.env.NEARAI_MODEL ?? 'z-ai/glm-5.3-flash';

async function main(): Promise<void> {
  if (!API_KEY) throw new Error('NEARAI_API_KEY is required');

  // Enable E2EE explicitly. Gateway TLS verification is enabled by default.
  // Attestations are reused for 60 minutes. Response records have a separate
  // 60-minute TTL, starting when the response finishes.
  const inferenceClient = new InferenceClient({
    apiKey: API_KEY,
    baseUrl: BASE_URL,
    ...transportOptions(),
    e2ee: true,
  });

  // Optional: verify ahead of the first message, for example on model selection.
  await inferenceClient.verify(MODEL);

  await runNonStreamingExample(inferenceClient);
  await runStreamingExample(inferenceClient);
}

async function runNonStreamingExample(
  inferenceClient: InferenceClient,
): Promise<void> {
  const completion = await inferenceClient.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 1024,
  });

  const verified = await inferenceClient.verifyResponse(completion.id);
  console.log(`Verified ${verified.signatureKind} response.`);
  console.log(completion.choices[0]?.message.content ?? '');
}

async function runStreamingExample(
  inferenceClient: InferenceClient,
): Promise<void> {
  const stream = await inferenceClient.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 1024,
    stream: true,
  });

  let completionId: string | undefined;
  for await (const chunk of stream) {
    completionId = chunk.id;
    process.stdout.write(chunk.choices[0]?.delta.content ?? '');
  }

  // Consume the full stream before verifying its exact bytes.
  process.stdout.write('\n');
  if (completionId === undefined)
    throw new Error('Stream returned no completion ID');
  const verified = await inferenceClient.verifyResponse(completionId);
  console.log(`Verified ${verified.signatureKind} streaming response.`);
}

await main();
