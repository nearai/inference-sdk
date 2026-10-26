import Anthropic from '@anthropic-ai/sdk';
import { InferenceClient } from '@nearai/inference-sdk/node';

const BASE_URL = process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1/';
const MODEL = process.env.NEARAI_MODEL ?? 'anthropic/claude-haiku-4-5';
const SIGNING_ALGO = 'ed25519';

async function main(): Promise<void> {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('NEARAI_API_KEY is required');

  const inferenceClient = new InferenceClient({
    apiKey,
    baseUrl: BASE_URL,
    signingAlgo: SIGNING_ALGO,
    ohttp: process.env.NEARAI_OHTTP === 'true',
  });

  const anthropic = new Anthropic({
    apiKey,
    // The official SDK appends /v1/messages to this API root.
    baseURL: inferenceClient.getBaseUrl().replace(/v1\/$/, ''),
    fetch: inferenceClient.fetch,
    maxRetries: 0,
  });

  await runNonStreamingExample(anthropic, inferenceClient);
  await runStreamingExample(anthropic, inferenceClient);
}

async function runNonStreamingExample(
  anthropic: Anthropic,
  inferenceClient: InferenceClient,
): Promise<void> {
  const message = await anthropic.messages.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_tokens: 128,
  });
  const verified = await inferenceClient.verifyResponse(message.id);
  console.log(`Verified ${verified.signatureKind} response.`);
  for (const block of message.content) {
    if (block.type === 'text') console.log(block.text);
  }
}

async function runStreamingExample(
  anthropic: Anthropic,
  inferenceClient: InferenceClient,
): Promise<void> {
  const stream = await anthropic.messages.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_tokens: 128,
    stream: true,
  });

  let messageId: string | undefined;
  let text = '';
  // Retain streamed text until the complete response has been verified.
  for await (const event of stream) {
    if (event.type === 'message_start') messageId = event.message.id;
    if (
      event.type === 'content_block_delta' &&
      event.delta.type === 'text_delta'
    )
      text += event.delta.text;
  }

  if (messageId === undefined) throw new Error('Stream returned no message ID');
  const verified = await inferenceClient.verifyResponse(messageId);
  console.log(`Verified ${verified.signatureKind} streaming response.`);
  console.log(text);
}

await main();
