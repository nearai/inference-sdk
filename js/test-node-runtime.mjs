import assert from 'node:assert/strict';
import { NearAiCloudClient } from './dist/index.js';

const client = new NearAiCloudClient({
  apiKey: 'test',
  fetch: () => ({
    ok: true,
    status: 200,
    text: () =>
      JSON.stringify({
        text: 'canonical-model:request:response',
        signature: '00',
        signing_address: `0x${'22'.repeat(20)}`,
        signing_algo: 'ecdsa',
        signature_kind: 'provider_tee',
      }),
  }),
});

const signature = await client.fetchCompletionSignature({
  completionId: 'chat-1',
});

assert.deepEqual(signature, {
  kind: 'provider_tee',
  signedText: 'canonical-model:request:response',
  signature: '00',
  signer: {
    signingAlgo: 'ecdsa',
    signingAddress: `0x${'22'.repeat(20)}`,
  },
});
