import assert from 'node:assert/strict';
import { test } from 'node:test';
import { TypeSafeClient, choice, noul, score } from '@typesafe-ai/sdk';
import { InferenceClient } from '../dist/node.js';
import { requiredEnv, retryReceipt, selectedModels } from './helpers.ts';

const credentialsAvailable = Boolean(
  process.env.NEARAI_API_KEY && process.env.NEARAI_BASE_URL,
);

for (const kind of ['gateway', 'provider_tee'] as const) {
  for (const signingAlgo of ['ed25519', 'ecdsa'] as const) {
    const skip = !credentialsAvailable
      ? 'Set NEARAI_API_KEY and NEARAI_BASE_URL to run live Jev SDK tests'
      : kind === 'provider_tee' && !process.env.NEARAI_JEV_SELF_HOSTED_MODEL
        ? 'Self-hosted Jev requires cloud-api#1285 and NEARAI_JEV_SELF_HOSTED_MODEL'
        : false;

    test(`official Jev SDK verifies ${kind} receipts with ${signingAlgo}`, {
      skip,
      timeout: 180_000,
    }, async () => {
      const model =
        kind === 'provider_tee'
          ? requiredEnv('NEARAI_JEV_SELF_HOSTED_MODEL')
          : (process.env.NEARAI_JEV_MODEL ??
            selectedModels('systemone').find(
              (entry) => entry.provider === 'external',
            )?.id);
      assert.ok(model, 'Select an external Jev model or set NEARAI_JEV_MODEL');

      const apiKey = requiredEnv('NEARAI_API_KEY');
      const inference = new InferenceClient({
        apiKey,
        baseUrl: requiredEnv('NEARAI_BASE_URL'),
        signingAlgo,
        e2ee: false,
        ohttp: false,
      });
      const preflight = await inference.verify(model);
      const selected = preflight.models.find(
        (report) =>
          report.signer.signingAlgo === signingAlgo && report.signingPublicKey,
      );
      if (kind === 'provider_tee') assert.ok(selected?.signingPublicKey);
      else assert.equal(preflight.models.length, 0);

      let inferenceRequests = 0;
      const jev = new TypeSafeClient({
        apiKey,
        baseURL: new URL('../', inference.getBaseUrl()).toString(),
        fetch: (input, init) => {
          inferenceRequests += 1;
          return inference.fetch(input, init);
        },
        compression: false,
        retry: { maxRetries: 0 },
        timeout: 60_000,
      });
      const { data, response } = await jev
        .systemOne({
          model,
          state: { message: 'I was charged twice. Please help.' },
          questions: {
            billing: noul('Is this about billing?'),
            team: choice('Choose a team.', {
              billing: 'Payments',
              support: 'Other',
            }),
            urgency: score('Rate urgency.', ['Routine', 'Urgent']),
          },
        })
        .withResponse();

      const id = response.headers.get('x-generation-id');
      assert.ok(id, 'Expected the NEAR receipt ID');
      const verified = await retryReceipt(() => inference.verifyResponse(id));
      assert.equal(verified.id, id);
      assert.equal(verified.signatureKind, kind);
      assert.equal(verified.signature.signer.signingAlgo, signingAlgo);
      if (kind === 'provider_tee') {
        assert.equal(
          verified.attestation.signer.signingAddress,
          selected?.signer.signingAddress,
        );
      }
      assert.equal(
        inferenceRequests,
        1,
        'Receipt retries must not repeat inference',
      );
      assert.equal(data.answers.billing.type, 'noul');
      assert.equal(data.answers.team.type, 'choice');
      assert.equal(data.answers.urgency.type, 'score');
      assert.ok(['billing', 'support'].includes(data.answers.team.choice));
    });
  }
}
