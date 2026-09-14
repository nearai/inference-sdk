import {
  AttestationClient,
  createPinnedTlsFetch,
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

const BASE_URL = 'https://cloud-api.near.ai/v1/';
const MODEL = 'z-ai/glm-5.3-flash';
const SIGNING_ALGO = 'ed25519';

await main();

async function main(): Promise<void> {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) {
    throw new Error('NEARAI_API_KEY is required');
  }

  const client = new AttestationClient({ apiKey, baseUrl: BASE_URL });

  // This bare example deliberately sends plaintext Chat JSON. It demonstrates
  // attestation and response-receipt verification, not the E2EE protocol.
  // Verify both deployments before sending either Chat request.
  const gateway = await fetchAndVerifyGateway(client);
  const models = await fetchAndVerifyModelAttestations(client);

  const pinnedTlsFetch = createGatewayPinnedTlsFetch(gateway);
  await runNonStreamingExample({
    apiKey,
    client,
    gateway,
    pinnedTlsFetch,
    models,
  });
  await runStreamingExample({
    apiKey,
    client,
    gateway,
    pinnedTlsFetch,
    models,
  });
}

async function runNonStreamingExample({
  apiKey,
  client,
  gateway,
  pinnedTlsFetch,
  models,
}: BareExampleContext): Promise<void> {
  const nonStreamingCompletion = await sendCompletion({
    apiKey,
    stream: false,
    pinnedTlsFetch,
  });
  await verifyCompletionReceipt({
    client,
    completion: nonStreamingCompletion,
    gateway,
    models,
  });
}

async function runStreamingExample({
  apiKey,
  client,
  gateway,
  pinnedTlsFetch,
  models,
}: BareExampleContext): Promise<void> {
  const streamingCompletion = await sendCompletion({
    apiKey,
    stream: true,
    pinnedTlsFetch,
  });
  await verifyCompletionReceipt({
    client,
    completion: streamingCompletion,
    gateway,
    models,
  });
}

async function fetchAndVerifyGateway(
  client: AttestationClient,
): Promise<VerifiedGatewayAttestation> {
  const fetched = await client.fetchGatewayAttestation({
    signingAlgo: SIGNING_ALGO,
  });
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
    model: MODEL,
    signingAlgo: SIGNING_ALGO,
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
  pinnedTlsFetch,
}: SendCompletionParams): Promise<Completion> {
  const requestBody = new TextEncoder().encode(
    JSON.stringify({
      model: MODEL,
      messages: [{ role: 'user', content: 'Reply with the word ok.' }],
      stream,
      max_completion_tokens: 8,
    }),
  );
  const response = await pinnedTlsFetch(
    new URL('chat/completions', BASE_URL),
    {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'Accept-Encoding': 'identity',
      [NO_ALIASING_HEADER]: 'true',
    },
      body: requestBody,
    },
  );
  const responseBody = new Uint8Array(await response.arrayBuffer());
  if (!response.ok) {
    throw new Error(
      `Chat request failed (${response.status}): ${new TextDecoder().decode(responseBody)}`,
    );
  }

  return {
    id: readCompletionId({ responseBody, stream }),
    label: stream ? 'Streaming completion' : 'Completion',
    requestBody,
    responseBody,
  };
}

function createGatewayPinnedTlsFetch(
  gateway: VerifiedGatewayAttestation,
): typeof globalThis.fetch {
  if (gateway.tlsBinding.kind !== 'attested') {
    throw new Error('Expected TLS-bound Gateway evidence');
  }
  return createPinnedTlsFetch(gateway.tlsBinding.spkiFingerprint);
}

async function verifyCompletionReceipt({
  client,
  completion,
  gateway,
  models,
}: VerifyCompletionReceiptParams): Promise<void> {
  const signature = await client.fetchCompletionSignature({
    completionId: completion.id,
    signingAlgo: SIGNING_ALGO,
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
  } else {
    verifyGatewayResponse({
      requestBody: completion.requestBody,
      responseBody: completion.responseBody,
      signature,
      attestation: gateway,
    });
    console.log(`${completion.label}: verified Gateway response receipt.`);
  }
}

function readCompletionId({
  responseBody,
  stream,
}: ReadCompletionIdParams): string {
  const responseText = new TextDecoder().decode(responseBody);
  if (!stream) {
    return readJsonCompletionId(responseText);
  }

  for (const line of responseText.split(/\r\n|\n|\r/)) {
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

type Completion = {
  readonly id: string;
  readonly label: string;
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
};

type SendCompletionParams = {
  readonly apiKey: string;
  readonly stream: boolean;
  readonly pinnedTlsFetch: typeof globalThis.fetch;
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

type BareExampleContext = {
  readonly apiKey: string;
  readonly client: AttestationClient;
  readonly gateway: VerifiedGatewayAttestation;
  readonly pinnedTlsFetch: typeof globalThis.fetch;
  readonly models: readonly VerifiedModelAttestation[];
};
