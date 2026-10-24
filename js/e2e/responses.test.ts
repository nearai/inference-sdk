import assert from 'node:assert/strict';
import { test } from 'node:test';
import OpenAI from 'openai';
import { InferenceClient } from '../dist/node.js';
import { requiredEnv, retryReceipt, selectedModels } from './helpers.ts';

const models = selectedModels('responses');
assert.equal(models.length, 2, 'Expected NEAR and OpenAI Responses models');

for (const { id: model } of models) {
  for (const ohttp of [false, true]) {
    test(`Responses ${model} JSON and SSE receipts, OHTTP=${ohttp}`, {
      timeout: 180_000,
    }, async (t) => {
      const apiKey = requiredEnv('NEARAI_API_KEY');
      const baseUrl = requiredEnv('NEARAI_BASE_URL');
      const client = new InferenceClient({
        apiKey,
        baseUrl,
        ohttp,
        e2ee: false,
      });
      const external = new OpenAI({
        apiKey,
        baseURL: baseUrl,
        fetch: client.fetch,
        maxRetries: 0,
      });
      const request = {
        model,
        input: 'Reply with the word OK.',
        store: false,
        max_output_tokens: 1024,
      };

      for (const stream of [false, true]) {
        let id: string;
        if (stream) {
          const events = await external.responses.create(
            { ...request, stream: true },
            { signal: t.signal },
          );
          let createdId: string | undefined;
          let completed = false;
          for await (const event of events) {
            if (event.type === 'response.created')
              createdId = event.response.id;
            if (event.type === 'response.completed') {
              assert.equal(event.response.id, createdId);
              assert.equal(event.response.status, 'completed');
              assert.ok(event.response.output.length);
              completed = true;
            }
          }
          assert.ok(
            createdId && completed,
            'SSE must reach response.completed and EOF',
          );
          id = createdId;
        } else {
          const result = await client.responses.create(request, {
            maxRetries: 0,
            signal: t.signal,
          });
          assert.equal(result.status, 'completed');
          assert.ok(result.output.length);
          id = result.id;
        }

        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          const receipt = await Promise.race([
            retryReceipt(() => client.verifyResponse(id), t.signal),
            new Promise<never>((_, reject) => {
              timer = setTimeout(
                () => reject(new Error('Receipt deadline exceeded')),
                15_000,
              );
            }),
          ]);
          assert.equal(receipt.id, id);
          assert.equal(receipt.signature.kind, 'gateway');
        } finally {
          clearTimeout(timer);
        }
      }
    });
  }
}
