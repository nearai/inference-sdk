import { NearAiSecureClient } from 'verifiable-ai-sdk/node';

const BASE_URL = 'https://cloud-api.near.ai/v1/';
const MODEL = 'z-ai/glm-5.3-flash';

await main();

async function main(): Promise<void> {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) {
    throw new Error('NEARAI_API_KEY is required');
  }

  const client = new NearAiSecureClient({ apiKey, baseUrl: BASE_URL });

  // This Node client uses Ed25519 for Gateway/model evidence and response
  // receipts. Before sending each request, it verifies fresh evidence for
  // `MODEL`, including the TLS peer that returned Gateway evidence. E2EE is
  // enabled by default.

  await runNonStreamingExample(client);
  await runStreamingExample(client);
}

async function runNonStreamingExample(
  client: NearAiSecureClient,
): Promise<void> {
  const { completion, receipt } =
    await client.chat.completions.createWithReceipt({
      model: MODEL,
      messages: [{ role: 'user', content: 'Reply with the word ok.' }],
      max_completion_tokens: 8,
    });

  console.log(completion.choices[0]?.message.content ?? '');

  // Receipt verification is optional and runs after the completion is available.
  const verified = await receipt.verify();
  console.log(`Verified ${verified.signatureKind} response receipt.`);
}

async function runStreamingExample(client: NearAiSecureClient): Promise<void> {
  const { stream, receipt: streamingReceipt } =
    await client.chat.completions.createWithReceipt({
      model: MODEL,
      messages: [{ role: 'user', content: 'Reply with the word ok.' }],
      max_completion_tokens: 8,
      stream: true,
    });

  for await (const chunk of stream) {
    process.stdout.write(chunk.choices[0]?.delta.content ?? '');
  }
  process.stdout.write('\n');

  const verifiedStream = await streamingReceipt.verify();
  console.log(`Verified ${verifiedStream.signatureKind} streaming receipt.`);
}
