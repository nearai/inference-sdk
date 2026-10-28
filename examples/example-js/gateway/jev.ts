import { readFile } from 'node:fs/promises';
import {
  InferenceClient,
  type SystemOneRequest,
} from '@nearai/inference-sdk/node';

async function main(): Promise<void> {
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
  let request: SystemOneRequest = {
    model,
    state: {
      message: 'I was charged twice for my subscription. Please help.',
    },
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
  };
  const imagePath = process.env.NEARAI_IMAGE_PATH;
  if (imagePath) {
    const imageBase64 = (await readFile(imagePath)).toString('base64');
    request = {
      model,
      state: {
        photo: {
          type: 'image_url',
          image_url: { url: `data:image/png;base64,${imageBase64}` },
        },
      },
      questions: {
        region: { type: 'box', instructions: 'the main object in `photo`' },
      },
    };
  }
  const result = await client.systemone.create(request, {
    signal: AbortSignal.timeout(120_000),
  });

  // decisionId comes from X-Generation-Id.
  // Verification hashes the exact bytes sent/received. Wait before acting on answers.
  const verified = await client.verifyResponse(result.decisionId);
  if (verified.signatureKind !== expectedKind) {
    throw new Error(
      `Expected ${expectedKind}, received ${verified.signatureKind}.`,
    );
  }
  console.log(
    `Verified ${verified.signatureKind} receipt ${result.decisionId} (${signingAlgo}).`,
  );
  console.log(
    JSON.stringify(
      { answers: result.data.answers, usage: result.data.usage },
      null,
      2,
    ),
  );
}

await main();
