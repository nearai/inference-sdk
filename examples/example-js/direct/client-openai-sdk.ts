import OpenAI from 'openai';
import { DirectInferenceClient } from '@nearai/inference-sdk/node';

const BASE_URL = 'https://glm-5-3-flash.completions.near.ai/v1';
const MODEL = 'z-ai/glm-5.3-flash';
const SIGNING_ALGO = 'ed25519';

async function main(): Promise<void> {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('NEARAI_API_KEY is required');

  // This client verifies the complete serving model-attestation set before
  // Chat. E2EE is enabled by default; direct TLS fingerprint binding is disabled.
  const directClient = new DirectInferenceClient({
    baseUrl: BASE_URL,
    apiKey,
    signingAlgo: SIGNING_ALGO,
  });

  // The OpenAI client uses DirectInferenceClient's verified transport.
  const openai = new OpenAI({
    apiKey,
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
    max_completion_tokens: 128,
  });
  console.log(completion.choices[0]?.message.content ?? '');

  const verified = await directClient.verifyResponse(completion.id);
  console.log(
    `Verified model response against ${verified.attestations.length} matching attestations.`,
  );
}

async function runStreamingExample(
  openai: OpenAI,
  directClient: DirectInferenceClient,
): Promise<void> {
  const stream = await openai.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 128,
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
