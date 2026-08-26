import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const packageDirectory = dirname(fileURLToPath(import.meta.url));
const entry = [
  `export { NearAiCloudClient } from ${JSON.stringify(
    join(packageDirectory, 'src/core/cloud-api.ts'),
  )};`,
  `export { verifyModelResponse } from ${JSON.stringify(
    join(packageDirectory, 'src/core/chat.ts'),
  )};`,
  `export { verifyModelAttestation } from ${JSON.stringify(
    join(packageDirectory, 'src/core/attestation-model.ts'),
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

  const cloudClient = new sdk.NearAiCloudClient({
    apiKey: 'test',
    fetch: () => ({
      ok: true,
      status: 200,
      text: () =>
        JSON.stringify({
          error_code: 'SIGNATURE_UNSUPPORTED',
          message: 'No provider signature',
        }),
    }),
  });
  assert.deepEqual(
    await cloudClient.lookupCompletionSignature({ completionId: 'chat-1' }),
    {
      status: 'unavailable',
      unavailable: {
        errorCode: 'SIGNATURE_UNSUPPORTED',
        message: 'No provider signature',
      },
    },
  );

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
  const signedText = await modelSignedText(
    'canonical-model',
    requestBody,
    responseBody,
  );

  const nonce = '11'.repeat(32);
  const signingAddress = '22'.repeat(20);
  const reportData = new Uint8Array(64);
  reportData.set(bytesFromHex(signingAddress));
  reportData.set(bytesFromHex(nonce), 32);
  assert.deepEqual(
    await sdk.verifyCloudModelReportDataBinding({
      nonce,
      reportData,
      reportedSpkiFingerprint: undefined,
      signingAddress,
    }),
    { kind: 'none' },
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

  const modelSigningAddress = '33'.repeat(32);
  const modelReportData = new Uint8Array(64);
  modelReportData.set(bytesFromHex(modelSigningAddress));
  modelReportData.set(bytesFromHex(nonce), 32);
  const appCompose = '{}';
  const appComposeHash = new Uint8Array(
    await globalThis.crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(appCompose),
    ),
  );
  const mrConfigId = new Uint8Array(48);
  mrConfigId[0] = 1;
  mrConfigId.set(appComposeHash, 1);
  const verifiedAttestation = await sdk.verifyModelAttestation({
    attestation: {
      nonce,
      signer: { algorithm: 'ed25519', address: modelSigningAddress },
      intelQuote: 'aa',
      eventLog: [{ digest: '00'.repeat(48), imr: 3 }],
      appCompose,
    },
    nonce,
    verifiers: {
      quote: async () => ({
        tcbStatus: 'UpToDate',
        advisoryIds: [],
        debugEnabled: false,
        reportData: modelReportData,
        mrConfigId,
        rtMr3: expectedRtmr3,
      }),
    },
  });

  assert.throws(
    () =>
      sdk.verifyModelResponse({
        requestBody,
        responseBody,
        signature: {
          kind: 'provider_tee',
          signature: '00',
          signer: {
            algorithm: 'ed25519',
            address: modelSigningAddress,
          },
          signedText,
        },
        attestation: verifiedAttestation,
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

async function modelSignedText(model, request, response) {
  return `${model}:${await sha256Hex(request)}:${await sha256Hex(response)}`;
}

async function sha256Hex(value) {
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-256', value),
  );
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

function bytesFromHex(value) {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
