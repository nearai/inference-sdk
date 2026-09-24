// Experimental direct-endpoint example. Use the Gateway examples for production.
import { DirectInferenceClient } from '@nearai/inference-sdk/node';

const BASE_URL = 'https://glm-5-3-flash.completions.near.ai/v1';
const MODEL = 'z-ai/glm-5.3-flash';
const SIGNING_ALGO = 'ed25519';

async function main(): Promise<void> {
  // Use a credential accepted by this direct endpoint. A Gateway API key is
  // not necessarily valid here.
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('NEARAI_API_KEY is required');

  // Direct model verification only: there is no Gateway attestation request.
  // E2EE is enabled by default; direct TLS fingerprint binding is disabled.
  // Every returned model attestation must pass before Chat is sent. Successful checks
  // are cached for 60 minutes.
  // Response signatures must belong to the selected model signer.
  const client = new DirectInferenceClient({
    baseUrl: BASE_URL,
    apiKey,
    signingAlgo: SIGNING_ALGO,
  });

  await runNonStreamingExample(client);
  await runStreamingExample(client);
}

async function runNonStreamingExample(
  client: DirectInferenceClient,
): Promise<void> {
  const completion = await client.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 128,
  });
  console.log(completion.choices[0]?.message.content ?? '');

  const verified = await client.verifyResponse(completion.id);
  console.log(
    `Verified model response against ${verified.attestations.length} matching attestations.`,
  );
}

async function runStreamingExample(
  client: DirectInferenceClient,
): Promise<void> {
  const stream = await client.chat.completions.create({
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
  const verified = await client.verifyResponse(completionId);
  console.log(
    `Verified streaming response against ${verified.attestations.length} matching attestations.`,
  );
}

await main();
