import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const packageDirectory = dirname(fileURLToPath(import.meta.url));
const entry = [
  `export { providerTeeSignatureText, verifyProviderTeeResponse } from ${JSON.stringify(
    join(packageDirectory, 'src/core/chat.ts'),
  )};`,
  `export { verifyCloudModelReportDataBinding } from ${JSON.stringify(
    join(packageDirectory, 'src/core/attestation-common.ts'),
  )};`,
  `export { verifyAndReplayRtmr3 } from ${JSON.stringify(
    join(packageDirectory, 'src/core/event-log.ts'),
  )};`,
  `export { normalizeVerifiedTdxQuote, verifyDcapQuote } from ${JSON.stringify(
    join(packageDirectory, 'src/utils/intel.ts'),
  )};`,
].join('\n');

const buildResult = await build({
  stdin: {
    contents: entry,
    loader: 'ts',
    resolveDir: packageDirectory,
    sourcefile: 'browser-runtime-entry.ts',
  },
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

// Node lazily initializes these Web APIs through internals that expect its
// global Buffer. Initialize them before simulating a browser global object.
await globalThis.fetch('data:,browser-runtime-test');
await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array());
const originalBuffer = globalThis.Buffer;
globalThis.Buffer = undefined;

try {
  const sdk = await import(moduleUrl);
  assert.equal(typeof sdk.verifyDcapQuote, 'function');

  const normalizedQuote = sdk.normalizeVerifiedTdxQuote({
    advisoryIds: [],
    debugEnabled: false,
    mrConfigId: new Uint8Array([0xcd]),
    reportData: new Uint8Array([0xab]),
    rtMr3: new Uint8Array([0xef]),
    tcbStatus: 'UpToDate',
  });
  assert.equal(normalizedQuote.reportData.toString('hex'), 'ab');

  const requestBody = new TextEncoder().encode('{"model":"canonical-model"}');
  const responseBody = new TextEncoder().encode('data: hello\n\n');
  assert.match(
    sdk.providerTeeSignatureText('canonical-model', requestBody, responseBody),
    /^canonical-model:[0-9a-f]{64}:[0-9a-f]{64}$/,
  );

  const nonce = '11'.repeat(32);
  const signingAddress = '22'.repeat(20);
  const reportData = new Uint8Array(64);
  reportData.set(bytesFromHex(signingAddress));
  reportData.set(bytesFromHex(nonce), 32);
  assert.deepEqual(
    await sdk.verifyCloudModelReportDataBinding({
      expectedNonce: nonce,
      reportData,
      reportedTlsCertFingerprint: undefined,
      signingAddress,
    }),
    { kind: 'signer_nonce' },
  );

  const expectedRtmr3 = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-384', new Uint8Array(96)),
  );
  assert.deepEqual(
    await sdk.verifyAndReplayRtmr3(
      [{ digest: '00'.repeat(48), imr: 3 }],
      expectedRtmr3,
    ),
    { composeHash: undefined, osImageHash: undefined },
  );

  const signatureText = sdk.providerTeeSignatureText(
    'canonical-model',
    requestBody,
    responseBody,
  );
  assert.throws(
    () =>
      sdk.verifyProviderTeeResponse({
        requestBody,
        responseBody,
        signature: {
          signature: '00',
          signature_kind: 'provider_tee',
          signing_address: '33'.repeat(32),
          signing_algo: 'ed25519',
          text: signatureText,
        },
        verifiedModelAttestation: {
          signingAddress: '33'.repeat(32),
          signingAlgo: 'ed25519',
        },
      }),
    (error) => {
      if (
        typeof error !== 'object' ||
        error === null ||
        !('failure' in error) ||
        typeof error.failure !== 'object' ||
        error.failure === null ||
        !('code' in error.failure)
      ) {
        return false;
      }
      return error.failure.code === 'signature.format_invalid';
    },
  );

  assert.equal(globalThis.Buffer, undefined);
} finally {
  globalThis.Buffer = originalBuffer;
}

function bytesFromHex(value) {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
