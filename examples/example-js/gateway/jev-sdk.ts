import { choice, noul, score } from '@typesafe-ai/sdk';
import { createVerifiedJevClients, receiptId } from './jev-helpers.ts';

const apiKey = process.env.NEARAI_API_KEY;
const model = process.env.NEARAI_MODEL;
if (!apiKey || !model) {
  throw new Error(
    'Set NEARAI_API_KEY and NEARAI_MODEL to your canonical Jev model ID.',
  );
}

const signingAlgo = process.env.NEARAI_SIGNING_ALGO ?? 'ed25519';
if (signingAlgo !== 'ed25519' && signingAlgo !== 'ecdsa') {
  throw new Error('NEARAI_SIGNING_ALGO must be ed25519 or ecdsa.');
}
const expectedKind = process.env.NEARAI_EXPECT_SIGNATURE_KIND ?? 'gateway';
if (expectedKind !== 'gateway' && expectedKind !== 'provider_tee') {
  throw new Error(
    'NEARAI_EXPECT_SIGNATURE_KIND must be gateway or provider_tee.',
  );
}

const { inference, jev } = createVerifiedJevClients({
  apiKey,
  signingAlgo,
  modelVerification:
    expectedKind === 'provider_tee' ? { policy: {} } : undefined,
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
        'Needs prompt attention',
        'Critical',
      ]),
    },
  })
  .withResponse();

// The NEAR receipt ID is distinct from the official SDK's requestId.
const id = receiptId(response);
const verified = await inference.verifyResponse(id);
if (verified.signatureKind !== expectedKind)
  throw new Error(
    `Expected ${expectedKind}, received ${verified.signatureKind}.`,
  );
console.log(`Verified ${verified.signatureKind} receipt ${verified.id}.`);
console.log(
  JSON.stringify({ answers: data.answers, usage: data.usage }, null, 2),
);
