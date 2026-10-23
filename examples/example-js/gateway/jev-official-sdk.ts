import { InferenceClient } from '@nearai/inference-sdk/node';
import { TypeSafeClient, choice, noul, score } from '@typesafe-ai/sdk';

const apiKey = process.env.NEARAI_API_KEY;
const model = process.env.NEARAI_MODEL;
if (!apiKey || !model) {
  throw new Error(
    'Set NEARAI_API_KEY and NEARAI_MODEL to your canonical Jev model ID.',
  );
}

const inference = new InferenceClient({
  apiKey,
  baseUrl: process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1/',
  e2ee: false,
  ohttp: false,
});
const jev = new TypeSafeClient({
  apiKey,
  // The official SDK appends /v1/systemone to its API root.
  baseURL: new URL('../', inference.getBaseUrl()).toString(),
  fetch: inference.fetch,
  compression: false,
  retry: { maxRetries: 0 },
  timeout: 60_000,
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
const id = response.headers.get('x-generation-id');
if (!id) throw new Error('Missing System One receipt ID.');
const verified = await inference.verifyResponse(id);
console.log(`Verified ${verified.signatureKind} receipt ${verified.id}.`);
console.log(data.answers);
