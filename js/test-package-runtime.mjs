import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import nacl from 'tweetnacl';
import {
  gatewaySignatureText,
  isVerificationError,
  VerificationError,
  verifyGatewayResponse,
} from './dist/index.js';

const requestBody = Buffer.from('{"model":"canonical-model"}');
const responseBody = Buffer.from('data: hello\n\n');
const keyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7));
const text = gatewaySignatureText(requestBody, responseBody);
const signature = Buffer.from(
  nacl.sign.detached(Buffer.from(text), keyPair.secretKey),
).toString('hex');

const result = verifyGatewayResponse({
  requestBody,
  responseBody,
  signature: {
    text,
    signature,
    signing_address: Buffer.from(keyPair.publicKey).toString('hex'),
    signing_algo: 'ed25519',
    signature_kind: 'gateway',
  },
  verifiedGatewayAttestation: {
    kind: 'gateway',
    signingAddress: Buffer.from(keyPair.publicKey).toString('hex'),
    signingAlgo: 'ed25519',
    reportDataBinding: {
      kind: 'signer_peer_tls_nonce',
      tlsCertFingerprint: '11'.repeat(32),
    },
    tcbStatus: 'UpToDate',
    advisoryIds: [],
    appCompose: '{}',
    imageDigests: [],
    runtimeMeasurements: {},
    provenanceVerified: false,
  },
});

assert.equal(result.scope, 'gateway');

const error = new VerificationError({
  phase: 'policy',
  code: 'policy.tcb_status_not_allowed',
  details: {
    target: 'near_model',
    actual: 'Revoked',
    allowed: ['UpToDate'],
    advisoryIds: [],
  },
});

assert.equal(isVerificationError(error), true);
assert.equal(error.failure.code, 'policy.tcb_status_not_allowed');
