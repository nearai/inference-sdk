import { DirectInferenceClient } from '@nearai/inference-sdk/node';
// Experimental direct-endpoint example.
import OpenAI from 'openai';
import { transportOptions } from '../utils/transport-options.ts';

const API_KEY = process.env.NEARAI_API_KEY;
const BASE_URL =
  process.env.NEARAI_BASE_URL ?? 'https://glm-5-3-flash.completions.near.ai/v1';
const MODEL = process.env.NEARAI_MODEL ?? 'z-ai/glm-5.3-flash';

async function main(): Promise<void> {
  if (!API_KEY) throw new Error('NEARAI_API_KEY is required');

  // Verify model reports and enable E2EE.
  const directClient = new DirectInferenceClient({
    baseUrl: BASE_URL,
    apiKey: API_KEY,
    ...transportOptions(),
    e2ee: true,
  });

  // The OpenAI client uses DirectInferenceClient's verified transport.
  const openai = new OpenAI({
    maxRetries: 0,
    apiKey: API_KEY,
    baseURL: BASE_URL,
    fetch: directClient.fetch,
  });

  await runNonStreamingExample(openai, directClient);
  await runStreamingExample(openai, directClient);
}

async function runNonStreamingExample(
  openai: OpenAI,
  directClient: DirectInferenceClient,
): Promise<void> {
  const completion = await openai.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 1024,
  });

  const verified = await directClient.verifyResponse(completion.id);
  console.log(
    `Verified model response against ${verified.attestations.length} matching attestations.`,
  );
  console.log(completion.choices[0]?.message.content ?? '');
}

async function runStreamingExample(
  openai: OpenAI,
  directClient: DirectInferenceClient,
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

  process.stdout.write('\n');
  if (completionId === undefined)
    throw new Error('Stream returned no completion ID');
  const verified = await directClient.verifyResponse(completionId);
  console.log(
    `Verified streaming response against ${verified.attestations.length} matching attestations.`,
  );
}

await main();
