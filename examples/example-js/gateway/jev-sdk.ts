import { choice, noul, score } from '@typesafe-ai/sdk';
import { createVerifiedJevClients, receiptId } from './jev-helpers.ts';

const apiKey = process.env.NEARAI_API_KEY;
const model = process.env.NEARAI_MODEL;
if (!apiKey || !model) {
  throw new Error(
    'Set NEARAI_API_KEY and NEARAI_MODEL to your canonical Jev model ID.',
  );
}

const { inference, jev } = createVerifiedJevClients({
  apiKey,
  baseUrl: process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1/',
});

const { data, response } = await jev
  .systemOne({
    model,
    state: { message: 'I was charged twice for my subscription. Please help.' },
    questions: {
      billing: noul('Is this about billing?'),
      team: choice('Which team should handle this?', {
        billing: 'Payments and subscriptions',
        support: 'Technical issues',
      }),
      urgency: score('How urgent is this request?', [
        'Routine',
        'Needs attention',
        'Critical',
      ]),
    },
  })
  .withResponse();

// The NEAR receipt ID is distinct from the official SDK's requestId.
const id = receiptId(response);
const verified = await inference.verifyResponse(id);
console.log(`Verified ${verified.signatureKind} receipt ${verified.id}.`);
console.log(data.answers);
