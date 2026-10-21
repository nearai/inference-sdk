import assert from 'node:assert/strict';
import { test } from 'node:test';
import { InferenceClient as GenericInferenceClient } from '../dist/index.js';
import {
  AttestationClient,
  createPinnedTlsFetch,
  InferenceClient,
  type SystemOneRequest,
  type SystemOneResponse,
  VerificationError,
  verifyGatewayAttestation,
  verifyGatewayResponse,
} from '../dist/node.js';
import { requiredEnv, retryReceipt, selectedModels } from './helpers.ts';

const BASE_URL = `${requiredEnv('NEARAI_BASE_URL').replace(/\/+$/, '')}/`;
const API_KEY = requiredEnv('NEARAI_API_KEY');
// The selector chooses a hosted Jev deployment, which has Gateway receipts.
const MODEL = selectedModels('systemone')[0]?.id;
assert.ok(MODEL, 'Expected a hosted Jev model for System One tests');
const REQUEST = {
  model: MODEL,
  state: { message: 'I was charged twice for my subscription. Please help.' },
  questions: {
    billing: { type: 'noul', instructions: 'Is this about billing?' },
    team: {
      type: 'choice',
      instructions: 'Which team should handle this?',
      criteria: {
        billing: 'Payments and subscriptions',
        support: 'Technical issues',
      },
    },
    urgency: {
      type: 'score',
      instructions: 'How urgent is this request?',
      criteria: ['Routine', 'Needs prompt attention', 'Critical'],
    },
  },
} satisfies SystemOneRequest;

for (const signingAlgo of ['ed25519', 'ecdsa'] as const) {
  test(`Node client verifies Jev decisions with ${signingAlgo}`, {
    timeout: 180_000,
  }, async () => {
    const client = new InferenceClient({
      apiKey: API_KEY,
      baseUrl: BASE_URL,
      signingAlgo,
      e2ee: false,
    });
    // create() verifies Gateway evidence and pins TLS before sending the decision.
    const result = await client.systemone.create(REQUEST);
    assert.ok(result.decisionId, 'Expected the X-Generation-Id receipt index');
    const verified = await retryReceipt(() =>
      client.verifyResponse(result.decisionId),
    );
    assert.equal(verified.id, result.decisionId);
    assert.equal(verified.signatureKind, 'gateway');
    assert.equal(verified.signature.signer.signingAlgo, signingAlgo);
    assert.equal(verified.attestation.tlsBinding.kind, 'attested');
    assertAnswers(result.data);
  });
}

test('Generic client verifies Jev decisions without peer TLS binding', {
  timeout: 180_000,
}, async () => {
  const client = new GenericInferenceClient({
    apiKey: API_KEY,
    baseUrl: BASE_URL,
  });
  const result = await client.systemone.create(REQUEST);
  const verified = await retryReceipt(() =>
    client.verifyResponse(result.decisionId),
  );
  assert.equal(verified.id, result.decisionId);
  assert.equal(verified.signatureKind, 'gateway');
  assert.equal(verified.attestation.tlsBinding.kind, 'none');
  assertAnswers(result.data);
});

test('Standalone APIs bind the generation ID to exact Jev request and response bytes', {
  timeout: 180_000,
}, async () => {
  const client = new AttestationClient({
    apiKey: API_KEY,
    baseUrl: BASE_URL,
  });
  const signingAlgo = 'ed25519';
  const fetchedGateway = await client.fetchGatewayAttestation({ signingAlgo });
  const gateway = await verifyGatewayAttestation({
    attestation: fetchedGateway.attestation,
    clientBinding: fetchedGateway.clientBinding,
  });
  assert.equal(gateway.tlsBinding.kind, 'attested');
  const pinnedTlsFetch = createPinnedTlsFetch(
    gateway.tlsBinding.spkiFingerprint,
  );
  const requestBody = new TextEncoder().encode(JSON.stringify(REQUEST));
  const response = await pinnedTlsFetch(new URL('systemone', BASE_URL), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      'Content-Type': 'application/json',
      'Accept-Encoding': 'identity',
      'x-no-aliasing': 'true',
    },
    body: requestBody,
  });
  assert.equal(response.status, 200, 'System One request must succeed');
  const decisionId = response.headers.get('x-generation-id');
  assert.ok(
    decisionId,
    'Expected X-Generation-Id even when the body has no id',
  );
  const responseBody = new Uint8Array(await response.arrayBuffer());
  const signature = await retryReceipt(() =>
    client.fetchCompletionSignature({ completionId: decisionId, signingAlgo }),
  );
  assert.equal(signature.kind, 'gateway');
  const params = { requestBody, responseBody, signature, attestation: gateway };
  verifyGatewayResponse(params);
  // A real receipt must reject changed bytes on either side, without inference.
  assert.throws(
    () =>
      verifyGatewayResponse({
        ...params,
        requestBody: new Uint8Array([...requestBody, 0x20]),
      }),
    VerificationError,
  );
  assert.throws(
    () =>
      verifyGatewayResponse({
        ...params,
        responseBody: new Uint8Array([...responseBody, 0x20]),
      }),
    VerificationError,
  );
});

function assertAnswers(response: SystemOneResponse): void {
  // The provider may return a dated revision instead of the catalog alias.
  assert.ok(response.model);
  assert.equal(response.answers.billing?.type, 'noul');
  assert.equal(response.answers.team?.type, 'choice');
  assert.equal(response.answers.urgency?.type, 'score');
  assert.ok(response.usage.input_tokens > 0);
  // Validate the response contract, not the model's probabilistic decision.
  if (response.answers.team.type === 'choice') {
    assert.ok(['billing', 'support'].includes(response.answers.team.choice));
  }
}
