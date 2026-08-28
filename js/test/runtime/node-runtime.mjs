import assert from 'node:assert/strict';
import { fetchCompletionSignature } from '../../dist/index.js';

const originalFetch = globalThis.fetch;
globalThis.fetch = async () =>
  new Response(
    JSON.stringify({
      text: 'canonical-model:request:response',
      signature: '00',
      signing_address: `0x${'22'.repeat(20)}`,
      signing_algo: 'ecdsa',
      signature_kind: 'provider_tee',
    }),
  );

let signature;
try {
  signature = await fetchCompletionSignature({
    apiKey: 'test',
    completionId: 'chat-1',
  });
} finally {
  globalThis.fetch = originalFetch;
}

assert.deepEqual(signature, {
  kind: 'provider_tee',
  signedText: 'canonical-model:request:response',
  signature: '00',
  signer: {
    signingAlgo: 'ecdsa',
    signingAddress: `0x${'22'.repeat(20)}`,
  },
});
