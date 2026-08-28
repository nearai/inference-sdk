import assert from 'node:assert/strict';
import {
  fetchGatewayAttestation,
  verifyGatewayAttestation,
} from 'verifiable-ai-sdk';

const apiKey = process.env.NEAR_AI_CLOUD_API_KEY;
if (!apiKey) {
  throw new Error('Set NEAR_AI_CLOUD_API_KEY before running this test.');
}

const fetchedGatewayAttestation = await fetchGatewayAttestation({ apiKey });
const peerSpkiFingerprint =
  fetchedGatewayAttestation.clientBinding.peerSpkiFingerprint;

assert.match(
  peerSpkiFingerprint ?? '',
  /^[0-9a-f]{64}$/,
  'Node should observe a SHA-256 TLS SPKI fingerprint',
);

const verifiedGatewayAttestation = await verifyGatewayAttestation(
  fetchedGatewayAttestation,
);

assert.deepEqual(verifiedGatewayAttestation.tlsBinding, {
  kind: 'peer',
  spkiFingerprint: peerSpkiFingerprint,
});

console.log(
  'Verified the production Gateway attestation with a peer TLS binding.',
);
