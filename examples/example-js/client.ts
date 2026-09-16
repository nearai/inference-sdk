import { SecureClient } from '@nearai/inference-sdk/node';

const BASE_URL = 'https://cloud-api.near.ai/v1/';
const MODEL = 'z-ai/glm-5.3-flash';
// Selects the algorithm for attestation, E2EE, and response signatures.
const SIGNING_ALGO = 'ed25519';

async function main(): Promise<void> {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('NEARAI_API_KEY is required');

  // E2EE and Gateway TLS verification are enabled by default.
  // Attestations are reused for 60 minutes. Response records have a separate
  // 60-minute TTL, starting when the response finishes.
  const secureClient = new SecureClient({
    apiKey,
    baseUrl: BASE_URL,
    signingAlgo: SIGNING_ALGO,
  });

  await runNonStreamingExample(secureClient);
  await runStreamingExample(secureClient);
}

async function runNonStreamingExample(
  secureClient: SecureClient,
): Promise<void> {
  const completion = await secureClient.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 8,
  });
  console.log(completion.choices[0]?.message.content ?? '');

  const verified = await secureClient.verifyResponse(completion.id);
  console.log(`Verified ${verified.signatureKind} response.`);
}

async function runStreamingExample(secureClient: SecureClient): Promise<void> {
  const stream = await secureClient.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 8,
    stream: true,
  });

  let completionId: string | undefined;
  for await (const chunk of stream) {
    completionId = chunk.id;
    process.stdout.write(chunk.choices[0]?.delta.content ?? '');
  }
  process.stdout.write('\n');

  // Consume the full stream before verifying its exact bytes.
  if (completionId === undefined)
    throw new Error('Stream returned no completion ID');
  const verified = await secureClient.verifyResponse(completionId);
  console.log(`Verified ${verified.signatureKind} streaming response.`);
}

await main();
