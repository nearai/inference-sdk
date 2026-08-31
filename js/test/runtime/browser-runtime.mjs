import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import nacl from 'tweetnacl';

const packageDirectory = join(dirname(fileURLToPath(import.meta.url)), '../..');
const buildResult = await build({
  entryPoints: [join(packageDirectory, 'src/index.ts')],
  bundle: true,
  format: 'esm',
  logLevel: 'silent',
  platform: 'browser',
  target: 'es2022',
  write: false,
});
const output = buildResult.outputFiles.at(0);
assert.ok(output, 'expected the browser bundle to contain JavaScript');

const moduleUrl = `data:text/javascript;base64,${Buffer.from(
  output.contents,
).toString('base64')}`;

// Node initializes Fetch and Web Crypto lazily through internals that read its
// global Buffer. Initialize them before simulating a browser where it is absent.
await globalThis.fetch('data:,browser-runtime-test');
await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array());
const originalBuffer = globalThis.Buffer;
const originalFetch = globalThis.fetch;
let gatewayAttestationUrl;
globalThis.Buffer = undefined;
globalThis.fetch = async (input) => {
  const url = new URL(
    typeof input === 'string' || input instanceof URL ? input : input.url,
  );
  if (url.pathname.endsWith('/attestation/report')) {
    gatewayAttestationUrl = url;
    return {
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify({
          gateway_attestation: {
            request_nonce: url.searchParams.get('nonce'),
            signing_algo: 'ed25519',
            signing_address: '55'.repeat(32),
            intel_quote: 'aa',
            event_log: [],
            info: { tcb_info: { app_compose: '{}' } },
            report_data: '00'.repeat(64),
          },
        }),
    };
  }
  return {
    ok: true,
    status: 200,
    text: async () =>
      JSON.stringify({
        text: 'canonical-model:request:response',
        signature: '00',
        signing_address: `0x${'22'.repeat(20)}`,
        signing_algo: 'ecdsa',
        signature_kind: 'provider_tee',
      }),
  };
};

try {
  const sdk = await import(moduleUrl);
  const fetchedSignature = await sdk.fetchCompletionSignature({
    apiKey: 'test',
    completionId: 'chat-1',
  });
  assert.equal(fetchedSignature.kind, 'provider_tee');

  const fetchedGatewayAttestation = await sdk.fetchGatewayAttestation({
    apiKey: 'test',
    policy: { verifyTlsBinding: false },
  });
  assert.equal(
    fetchedGatewayAttestation.clientBinding.nonce,
    fetchedGatewayAttestation.attestation.nonce,
  );
  assert.equal(
    fetchedGatewayAttestation.clientBinding.peerSpkiFingerprint,
    undefined,
  );
  assert.equal(fetchedGatewayAttestation.policy.verifyTlsBinding, false);
  assert.equal(
    gatewayAttestationUrl.searchParams.get('include_tls_fingerprint'),
    'false',
  );

  const requestBody = new TextEncoder().encode(
    JSON.stringify({ model: 'canonical-model' }),
  );
  const responseBody = new TextEncoder().encode('data: hello\n\n');
  const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(7));
  const signer = {
    signingAlgo: 'ed25519',
    signingAddress: hex(keyPair.publicKey),
  };
  const signedText = `canonical-model:${await sha256Hex(
    requestBody,
  )}:${await sha256Hex(responseBody)}`;
  const signature = hex(
    nacl.sign.detached(new TextEncoder().encode(signedText), keyPair.secretKey),
  );

  sdk.verifyModelResponse({
    requestBody,
    responseBody,
    signature: {
      kind: 'provider_tee',
      signedText,
      signature,
      signer,
    },
    attestation: { signer },
  });

  assert.equal(globalThis.Buffer, undefined);
} finally {
  globalThis.Buffer = originalBuffer;
  globalThis.fetch = originalFetch;
}

async function sha256Hex(value) {
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-256', value),
  );
  return hex(digest);
}

function hex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}
