import {
  AttestationClient,
  findModelAttestationForSignature,
  NO_ALIASING_HEADER,
  verifyGatewayAttestation,
  verifyGatewayResponse,
  verifyModelAttestation,
  verifyModelResponse,
} from 'verifiable-ai-sdk/node';
import type {
  VerifiedGatewayAttestation,
  VerifiedModelAttestation,
} from 'verifiable-ai-sdk/node';

const apiUrl = 'https://cloud-api.near.ai/v1/chat/completions';
const model = 'z-ai/glm-5.2';
const signingAlgo = 'ed25519';
const decoder = new TextDecoder();
const encoder = new TextEncoder();

type Completion = {
  readonly id: string;
  readonly label: string;
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
};

type SendCompletionParams = {
  readonly apiKey: string;
  readonly stream: boolean;
};

type ReadCompletionIdParams = {
  readonly responseBody: Uint8Array;
  readonly stream: boolean;
};

type VerifyCompletionReceiptParams = {
  readonly client: AttestationClient;
  readonly completion: Completion;
  readonly gateway: VerifiedGatewayAttestation;
  readonly models: readonly VerifiedModelAttestation[];
};

const apiKey = process.env.NEARAI_API_KEY;
if (!apiKey) {
  throw new Error('NEARAI_API_KEY is required');
}

const client = new AttestationClient({ apiKey });

// Verify both deployments before sending either Chat request.
const gateway = await fetchAndVerifyGateway(client);
const models = await fetchAndVerifyModelAttestations(client);

for (const stream of [false, true]) {
  const completion = await sendCompletion({ apiKey, stream });
  await verifyCompletionReceipt({ client, completion, gateway, models });
}

async function fetchAndVerifyGateway(
  client: AttestationClient,
): Promise<VerifiedGatewayAttestation> {
  const fetched = await client.fetchGatewayAttestation({ signingAlgo });
  const verified = await verifyGatewayAttestation({
    attestation: fetched.attestation,
    clientBinding: fetched.clientBinding,
  });
  console.log('Gateway deployment: verified.');
  return verified;
}

async function fetchAndVerifyModelAttestations(
  client: AttestationClient,
): Promise<readonly VerifiedModelAttestation[]> {
  const fetched = await client.fetchModelAttestations({
    model,
    signingAlgo,
  });
  if (fetched.attestations.length === 0) {
    throw new Error('Gateway returned no model attestations');
  }

  const verified = await Promise.all(
    fetched.attestations.map((attestation) =>
      verifyModelAttestation({
        attestation,
        clientBinding: fetched.clientBinding,
      }),
    ),
  );
  console.log(`Model deployments: verified ${verified.length}.`);
  return verified;
}

async function sendCompletion({
  apiKey,
  stream,
}: SendCompletionParams): Promise<Completion> {
  const requestBody = encoder.encode(
    JSON.stringify({
      model,
      messages: [{ role: 'user', content: 'Reply with the word ok.' }],
      stream,
      max_completion_tokens: 8,
    }),
  );
  const response = await fetch(apiUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'Accept-Encoding': 'identity',
      [NO_ALIASING_HEADER]: 'true',
    },
    body: requestBody,
  });
  const responseBody = new Uint8Array(await response.arrayBuffer());
  if (!response.ok) {
    throw new Error(
      `Chat request failed (${response.status}): ${decoder.decode(responseBody)}`,
    );
  }

  return {
    id: readCompletionId({ responseBody, stream }),
    label: stream ? 'Streaming completion' : 'Completion',
    requestBody,
    responseBody,
  };
}

async function verifyCompletionReceipt({
  client,
  completion,
  gateway,
  models,
}: VerifyCompletionReceiptParams): Promise<void> {
  const signature = await client.fetchCompletionSignature({
    completionId: completion.id,
    signingAlgo,
  });

  if (signature.kind === 'provider_tee') {
    const attestation = findModelAttestationForSignature({
      attestations: models,
      signature,
    });
    verifyModelResponse({
      requestBody: completion.requestBody,
      responseBody: completion.responseBody,
      signature,
      attestation,
    });
    console.log(`${completion.label}: verified model response receipt.`);
    return;
  }

  verifyGatewayResponse({
    requestBody: completion.requestBody,
    responseBody: completion.responseBody,
    signature,
    attestation: gateway,
  });
  console.log(`${completion.label}: verified Gateway response receipt.`);
}

function readCompletionId({
  responseBody,
  stream,
}: ReadCompletionIdParams): string {
  if (!stream) {
    return readJsonCompletionId(decoder.decode(responseBody));
  }

  for (const line of decoder.decode(responseBody).split(/\r\n|\n|\r/)) {
    if (!line.startsWith('data: ') || line === 'data: [DONE]') {
      continue;
    }
    try {
      return readJsonCompletionId(line.slice('data: '.length));
    } catch {
      // Later events may contain the completion ID.
    }
  }
  throw new Error('Streaming Chat response did not contain an id');
}

function readJsonCompletionId(text: string): string {
  const response = JSON.parse(text) as { id?: unknown };
  if (typeof response.id !== 'string' || response.id.length === 0) {
    throw new Error('Chat response did not contain an id');
  }
  return response.id;
}
