import {
  AttestationClient,
  createPinnedTlsFetch,
  prepareE2eeChatRequest,
  verifyGatewayAttestation,
  verifyGatewayResponse,
  verifyModelAttestation,
  verifyModelResponse,
} from '@nearai/inference-sdk/node';
import type {
  VerifiedGatewayAttestation,
  VerifiedModelAttestation,
} from '@nearai/inference-sdk/node';

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

  // Verify both deployments before sending either Chat request.
  const gateway = await fetchAndVerifyGateway(client);
  const models = await fetchAndVerifyModelAttestations(client);
  const modelAttestation = models.find(
    (attestation) =>
      attestation.signer.signingAlgo === SIGNING_ALGO &&
      attestation.signingPublicKey !== undefined,
  );
  if (modelAttestation === undefined) {
    throw new Error('No verified model public key is available for E2EE');
  }

  const pinnedTlsFetch = createGatewayPinnedTlsFetch(gateway);
  await runNonStreamingExample({
    apiKey,
    client,
    gateway,
    pinnedTlsFetch,
    modelAttestation,
  });
  await runStreamingExample({
    apiKey,
    client,
    gateway,
    pinnedTlsFetch,
    modelAttestation,
  });
}

async function runNonStreamingExample({
  apiKey,
  client,
  gateway,
  pinnedTlsFetch,
  modelAttestation,
}: BareExampleContext): Promise<void> {
  const nonStreamingCompletion = await sendCompletion({
    apiKey,
    stream: false,
    pinnedTlsFetch,
    modelAttestation,
  });
  await verifyCompletionReceipt({
    client,
    completion: nonStreamingCompletion,
    gateway,
    modelAttestation,
  });
}

async function runStreamingExample({
  apiKey,
  client,
  gateway,
  pinnedTlsFetch,
  modelAttestation,
}: BareExampleContext): Promise<void> {
  const streamingCompletion = await sendCompletion({
    apiKey,
    stream: true,
    pinnedTlsFetch,
    modelAttestation,
  });
  await verifyCompletionReceipt({
    client,
    completion: streamingCompletion,
    gateway,
    modelAttestation,
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
  modelAttestation,
}: SendCompletionParams): Promise<Completion> {
  const request = new Request(new URL('chat/completions', BASE_URL), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'Accept-Encoding': 'identity',
    },
    body: JSON.stringify({
      model: MODEL,
      messages: [{ role: 'user', content: 'Reply with the word ok.' }],
      stream,
      max_completion_tokens: 8,
    }),
  });
  const prepared = await prepareE2eeChatRequest({
    request,
    attestation: modelAttestation,
  });

  // Capture the encrypted bytes sent, before either body is decrypted.
  const requestBytes = await prepared.request.clone().arrayBuffer();
  const requestBody = new Uint8Array(requestBytes);
  const response = await pinnedTlsFetch(prepared.request);
  if (!response.ok) {
    throw new Error(
      `Chat request failed (${response.status}): ${await response.text()}`,
    );
  }
  const encryptedResponse = response.clone();
  const decryptedResponse = await prepared.decryptResponse(response);
  const [responseBytes, plaintextBody] = await Promise.all([
    encryptedResponse.arrayBuffer(),
    readDecryptedCompletion({ response: decryptedResponse, stream }),
  ]);

  return {
    id: readCompletionId({ responseText: plaintextBody, stream }),
    label: stream ? 'Streaming completion' : 'Completion',
    requestBody,
    responseBody: new Uint8Array(responseBytes),
  };
}

async function readDecryptedCompletion({
  response,
  stream,
}: ReadDecryptedCompletionParams): Promise<string> {
  if (!stream) {
    const responseText = await response.text();
    console.log(responseText);
    return responseText;
  }
  if (response.body === null) {
    throw new Error('Streaming Chat response has no body');
  }
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let responseText = '';
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      // Display decrypted SSE as it arrives while retaining it for the ID.
      process.stdout.write(chunk.value);
      responseText += chunk.value;
    }
  } finally {
    reader.releaseLock();
  }
  return responseText;
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
  modelAttestation,
}: VerifyCompletionReceiptParams): Promise<void> {
  const signature = await client.fetchCompletionSignature({
    completionId: completion.id,
    signingAlgo: SIGNING_ALGO,
  });

  if (signature.kind === 'provider_tee') {
    verifyModelResponse({
      requestBody: completion.requestBody,
      responseBody: completion.responseBody,
      signature,
      attestation: modelAttestation,
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
  responseText,
  stream,
}: ReadCompletionIdParams): string {
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
  const response: unknown = JSON.parse(text);
  if (
    typeof response !== 'object' ||
    response === null ||
    !('id' in response) ||
    typeof response.id !== 'string' ||
    response.id.length === 0
  ) {
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
  readonly modelAttestation: VerifiedModelAttestation;
};

type ReadCompletionIdParams = {
  readonly responseText: string;
  readonly stream: boolean;
};

type ReadDecryptedCompletionParams = {
  readonly response: Response;
  readonly stream: boolean;
};

type VerifyCompletionReceiptParams = {
  readonly client: AttestationClient;
  readonly completion: Completion;
  readonly gateway: VerifiedGatewayAttestation;
  readonly modelAttestation: VerifiedModelAttestation;
};

type BareExampleContext = {
  readonly apiKey: string;
  readonly client: AttestationClient;
  readonly gateway: VerifiedGatewayAttestation;
  readonly pinnedTlsFetch: typeof globalThis.fetch;
  readonly modelAttestation: VerifiedModelAttestation;
};
