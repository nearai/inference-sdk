import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import {
  findModelAttestationForSigner,
  isVerificationError,
  NearAiCloudClient,
  VerificationError,
  verifyGatewayAttestation,
  verifyGatewayResponse,
} from './dist/index.js';

const requestBody = Buffer.from('{"model":"canonical-model"}');
const responseBody = Buffer.from('data: hello\n\n');
const keyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7));
const signerAddress = Buffer.from(keyPair.publicKey).toString('hex');
const signedText = gatewaySignedText(requestBody, responseBody);
const signature = Buffer.from(
  nacl.sign.detached(Buffer.from(signedText), keyPair.secretKey),
).toString('hex');
const nonce = '11'.repeat(32);
const peerSpkiFingerprint = '33'.repeat(32);
const appCompose = '{}';
const reportData = Buffer.concat([
  createHash('sha256')
    .update(
      Buffer.concat([
        Buffer.from(signerAddress, 'hex'),
        Buffer.from(peerSpkiFingerprint, 'hex'),
      ]),
    )
    .digest(),
  Buffer.from(nonce, 'hex'),
]);
const rtMr3 = createHash('sha384')
  .update(Buffer.concat([Buffer.alloc(48), Buffer.alloc(48)]))
  .digest();
const mrConfigId = Buffer.concat([
  Buffer.from([1]),
  createHash('sha256').update(appCompose).digest(),
  Buffer.alloc(15),
]);
const attestation = await verifyGatewayAttestation({
  attestation: {
    nonce,
    signer: { algorithm: 'ed25519', address: signerAddress },
    intelQuote: 'aa',
    eventLog: [{ digest: '00'.repeat(48), imr: 3 }],
    appCompose,
    declaredSpkiFingerprint: peerSpkiFingerprint,
    reportedQuoteData: reportData.toString('hex'),
  },
  nonce,
  peerSpkiFingerprint,
  verifiers: {
    quote: async () => ({
      tcbStatus: 'UpToDate',
      advisoryIds: [],
      debugEnabled: false,
      reportData,
      mrConfigId,
      rtMr3,
    }),
  },
});

assert.equal(
  verifyGatewayResponse({
    requestBody,
    responseBody,
    signature: {
      kind: 'gateway',
      signedText,
      signature,
      signer: { algorithm: 'ed25519', address: signerAddress },
    },
    attestation,
  }),
  undefined,
);

const error = new VerificationError({
  phase: 'policy',
  code: 'policy.tcb_status_not_allowed',
  details: {
    actual: 'Revoked',
    accepted: ['UpToDate'],
    advisoryIds: [],
  },
});

assert.equal(isVerificationError(error), true);
assert.equal(error.failure.code, 'policy.tcb_status_not_allowed');

const cloudClient = new NearAiCloudClient({
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

const modelAttestation = {
  nonce,
  signer: { algorithm: 'ecdsa', address: '22'.repeat(20) },
  intelQuote: 'aa',
  eventLog: [],
  appCompose: '{}',
};
assert.deepEqual(
  findModelAttestationForSigner({
    attestations: [modelAttestation],
    signer: modelAttestation.signer,
  }),
  modelAttestation,
);

function gatewaySignedText(request, response) {
  return `${hashBytes(request)}:${hashBytes(response)}`;
}

function hashBytes(value) {
  return createHash('sha256').update(value).digest('hex');
}
