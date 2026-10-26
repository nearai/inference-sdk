import type { SigningAlgo } from '@nearai/inference-sdk/node';
import { InferenceClient } from '@nearai/inference-sdk/node';
import OpenAI from 'openai';
import { transportOptions } from '../transport-options.ts';

const BASE_URL = process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1/';
const MODEL = process.env.NEARAI_MODEL ?? 'z-ai/glm-5.3-flash';
// Selects the algorithm for attestation, E2EE, and response signatures.
const SIGNING_ALGO = (process.env.NEARAI_SIGNING_ALGO ??
  'ed25519') as SigningAlgo;

async function main(): Promise<void> {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('NEARAI_API_KEY is required');

  // Enable E2EE explicitly. Gateway TLS verification is enabled by default.
  // Attestations are reused for 60 minutes. Response records have a separate
  // 60-minute TTL, starting when the response finishes.
  const inferenceClient = new InferenceClient({
    apiKey,
    baseUrl: BASE_URL,
    ...transportOptions(SIGNING_ALGO),
    e2ee: true,
  });

  // Both clients are created once and reused, including for concurrent calls.
  const openai = new OpenAI({
    maxRetries: 0,
    apiKey,
    baseURL: BASE_URL,
    fetch: inferenceClient.fetch,
  });

  await runNonStreamingExample(openai, inferenceClient);
  await runStreamingExample(openai, inferenceClient);
}

async function runNonStreamingExample(
  openai: OpenAI,
  inferenceClient: InferenceClient,
): Promise<void> {
  const completion = await openai.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 1024,
  });

  const verified = await inferenceClient.verifyResponse(completion.id);
  console.log(`Verified ${verified.signatureKind} response.`);
  console.log(completion.choices[0]?.message.content ?? '');
}

async function runStreamingExample(
  openai: OpenAI,
  inferenceClient: InferenceClient,
): Promise<void> {
  const stream = await openai.chat.completions.create({
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
