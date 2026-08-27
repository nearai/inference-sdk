import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import * as sdk from './dist/index.js';

const {
  findModelAttestationForSignature,
  isVerificationError,
  NearAiCloudClient,
  VerificationError,
  verifyGatewayAttestation,
  verifyGatewayResponse,
} = sdk;

assert.equal('generateNonce' in sdk, false);

const requestBody = Buffer.from('{"model":"canonical-model"}');
const responseBody = Buffer.from('data: hello\n\n');
const keyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7));
const signingAddress = Buffer.from(keyPair.publicKey).toString('hex');
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
        Buffer.from(signingAddress, 'hex'),
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
    signer: { signingAlgo: 'ed25519', signingAddress },
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
      signer: { signingAlgo: 'ed25519', signingAddress },
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

let gatewayAttestationUrl;
const gatewayAttestationClient = new NearAiCloudClient({
  apiKey: 'test',
  fetch: (input) => {
    gatewayAttestationUrl = new URL(input.toString());
    const requestNonce = gatewayAttestationUrl.searchParams.get('nonce');
    assert.ok(requestNonce, 'expected a client nonce in the request URL');

    return {
      ok: true,
      status: 200,
      text: () =>
        JSON.stringify({
          gateway_attestation: gatewayAttestationResponse(requestNonce),
        }),
    };
  },
});
const fetchedGatewayAttestation =
  await gatewayAttestationClient.fetchGatewayAttestation();

assert.match(fetchedGatewayAttestation.nonce, /^[0-9a-f]{64}$/);
assert.equal(
  gatewayAttestationUrl.searchParams.get('nonce'),
  fetchedGatewayAttestation.nonce,
);
assert.equal(
  fetchedGatewayAttestation.attestation.nonce,
  fetchedGatewayAttestation.nonce,
);

const modelAttestation = {
  nonce,
  signer: { signingAlgo: 'ecdsa', signingAddress: '22'.repeat(20) },
  intelQuote: 'aa',
  eventLog: [],
  appCompose: '{}',
};
assert.deepEqual(
  findModelAttestationForSignature({
    attestations: [modelAttestation],
    signature: {
      kind: 'provider_tee',
      signedText: 'canonical-model:request:response',
      signature: '00',
      signer: modelAttestation.signer,
    },
  }),
  modelAttestation,
);

function gatewaySignedText(request, response) {
  return `${hashBytes(request)}:${hashBytes(response)}`;
}

function hashBytes(value) {
  return createHash('sha256').update(value).digest('hex');
}

function gatewayAttestationResponse(requestNonce) {
  return {
    request_nonce: requestNonce,
    signing_algo: 'ed25519',
    signing_address: signingAddress,
    intel_quote: 'aa',
    event_log: [],
    info: { tcb_info: { app_compose: '{}' } },
    tls_cert_fingerprint: peerSpkiFingerprint,
    report_data: '00'.repeat(64),
  };
}
