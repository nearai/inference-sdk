import { NearAiSecureClient } from 'verifiable-ai-sdk/node';

const model = 'z-ai/glm-5.2';
const apiKey = process.env.NEARAI_API_KEY;

if (!apiKey) {
  throw new Error('NEARAI_API_KEY is required');
}

const client = new NearAiSecureClient({ apiKey });

// Before sending this request, the client verifies fresh Gateway and model
// evidence for `model`. E2EE is enabled by default.
const { completion, receipt } =
  await client.chat.completions.createWithReceipt({
    model,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_tokens: 8,
  });

console.log(completion.choices[0]?.message.content ?? '');

// Receipt verification is optional and runs after the completion is available.
const verified = await receipt.verify();
console.log(`Verified ${verified.signatureKind} response receipt.`);
