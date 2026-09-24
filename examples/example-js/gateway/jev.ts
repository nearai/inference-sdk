import { InferenceClient } from '@nearai/inference-sdk/node';

const apiKey = process.env.NEARAI_API_KEY;
const model = process.env.NEARAI_MODEL;
if (!apiKey || !model) {
  throw new Error(
    'Set NEARAI_API_KEY and NEARAI_MODEL to your registered canonical Jev model ID.',
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

// The Node client verifies Gateway attestation and pins subsequent HTTPS
// requests to its attested TLS key. System One does not support E2EE or OHTTP.
const client = new InferenceClient({
  apiKey,
  baseUrl: process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1',
  signingAlgo,
  e2ee: false,
  ohttp: false,
  // Requiring model evidence also blocks external-only models before inference.
  modelVerification:
    expectedKind === 'provider_tee' ? { policy: {} } : undefined,
});
const result = await client.systemone.create(
  {
    model,
    state: { message: 'I was charged twice for my subscription. Please help.' },
    questions: {
      billing: { type: 'noul', instructions: 'Is this about billing?' },
      team: {
        type: 'choice',
        instructions: 'Which team should handle this?',
        criteria: {
          billing: 'Payments and subscriptions',
          support: 'Technical issues',
        },
      },
      urgency: {
        type: 'score',
        instructions: 'How urgent is this request?',
        criteria: ['Routine', 'Needs prompt attention', 'Critical'],
      },
    },
  },
  { signal: AbortSignal.timeout(60_000) },
);

// Lookup uses X-Signature-Id, not the optional upstream JSON id. Verification
// hashes the exact bytes sent/received. Do not act on answers until this passes.
const verified = await result.verify();
if (verified.signatureKind !== expectedKind) {
  throw new Error(
    `Expected ${expectedKind}, received ${verified.signatureKind}.`,
  );
}
console.log(
  `Verified ${verified.signatureKind} receipt ${result.signatureId} (${signingAlgo}).`,
);
console.log(
  verified.signatureKind === 'gateway'
    ? 'Gateway receipt: integrity and Gateway provenance; not proof of TypeSafe model execution in a TEE.'
    : 'Provider TEE receipt: response signed by the matching verified model deployment.',
);
console.log(
  JSON.stringify(
    { answers: result.data.answers, usage: result.data.usage },
    null,
    2,
  ),
);
