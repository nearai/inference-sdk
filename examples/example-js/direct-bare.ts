import {
  DirectAttestationClient,
  createPinnedTlsFetch,
  verifyDirectModelAttestations,
  verifyDirectModelResponse,
  type VerifiedDirectModelAttestation,
} from '@nearai/inference-sdk/node';

// Standalone verification and HTTPS pinning. This example sends plaintext Chat
// bodies over HTTPS; it does not implement E2EE. See direct-client.ts for E2EE.
const BASE_URL = 'https://glm-5-3-flash.completions.near.ai/v1/';
const MODEL = 'z-ai/glm-5.3-flash';
const SIGNING_ALGO = 'ed25519';

async function main(): Promise<void> {
  // Direct endpoint credentials may differ from Gateway API keys.
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('NEARAI_API_KEY is required');

  const client = new DirectAttestationClient({ apiKey, baseUrl: BASE_URL });
  const fetched = await client.fetchModelAttestations({
    signingAlgo: SIGNING_ALGO,
  });
  const verified = await verifyDirectModelAttestations(fetched);
  console.log(
    `Verified ${verified.attestations.length} direct model attestations.`,
  );

  if (verified.tlsBinding.kind !== 'attested') {
    throw new Error('Expected TLS-bound direct model attestations');
  }
  // Pin Chat requests to the verified endpoint TLS keys.
  const pinnedTlsFetch = createPinnedTlsFetch(verified.spkiFingerprints);
  const params: CompletionExampleParams = {
    apiKey,
    client,
    pinnedTlsFetch,
    attestations: verified.attestations,
  };
  await runNonStreamingExample(params);
  await runStreamingExample(params);
}

async function runNonStreamingExample(
  params: CompletionExampleParams,
): Promise<void> {
  const { requestBody, response } = await sendChatRequest({
    ...params,
    stream: false,
  });
  const responseBytes = await response.arrayBuffer();
  const responseBody = new Uint8Array(responseBytes);
  const responseText = new TextDecoder().decode(responseBody);
  const completion = JSON.parse(responseText);
  console.log(completion.choices[0]?.message.content ?? '');

  await verifyResponse({
    ...params,
    completionId: completion.id,
    requestBody,
    responseBody,
  });
}

async function runStreamingExample(
  params: CompletionExampleParams,
): Promise<void> {
  const { requestBody, response } = await sendChatRequest({
    ...params,
    stream: true,
  });
  if (response.body === null) throw new Error('Streaming response has no body');

  // Read one copy for exact-byte verification while displaying the SSE stream.
  const responseBytesPromise = response.clone().arrayBuffer();
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let responseText = '';
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      process.stdout.write(chunk.value);
      responseText += chunk.value;
    }
  } finally {
    reader.releaseLock();
  }
  const responseBytes = await responseBytesPromise;
  const responseBody = new Uint8Array(responseBytes);
  const completionId = readStreamCompletionId(responseText);
  await verifyResponse({ ...params, completionId, requestBody, responseBody });
}

async function sendChatRequest({
  apiKey,
  pinnedTlsFetch,
  stream,
}: SendChatRequestParams): Promise<SentChatRequest> {
  const body = JSON.stringify({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 128,
    stream,
  });
  const requestBody = new TextEncoder().encode(body);
  const response = await pinnedTlsFetch(new URL('chat/completions', BASE_URL), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'Accept-Encoding': 'identity',
    },
    body,
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(`Chat request failed (${response.status}): ${message}`);
  }
  return { requestBody, response };
}

async function verifyResponse({
  client,
  completionId,
  requestBody,
  responseBody,
  attestations,
}: VerifyResponseParams): Promise<void> {
  const signature = await client.fetchCompletionSignature({
    completionId,
    signingAlgo: SIGNING_ALGO,
  });
  const matching = verifyDirectModelResponse({
    requestBody,
    responseBody,
    signature,
    attestations,
  });
  // Keep every verified attestation matching the response signer.
  console.log(
    `Verified model response against ${matching.length} matching attestations.`,
  );
}

function readStreamCompletionId(responseText: string): string {
  for (const line of responseText.split(/\r\n|\n|\r/)) {
    if (!line.startsWith('data:')) continue;
    const data = line.slice('data:'.length).trim();
    if (data === '[DONE]') continue;
    const chunk = JSON.parse(data);
    if (typeof chunk.id === 'string') return chunk.id;
  }
  throw new Error('Stream returned no completion ID');
}

type CompletionExampleParams = {
  readonly apiKey: string;
  readonly client: DirectAttestationClient;
  readonly pinnedTlsFetch: typeof globalThis.fetch;
  readonly attestations: readonly VerifiedDirectModelAttestation[];
};

type SendChatRequestParams = Pick<
  CompletionExampleParams,
  'apiKey' | 'pinnedTlsFetch'
> & {
  readonly stream: boolean;
};

type SentChatRequest = {
  readonly requestBody: Uint8Array;
  readonly response: Response;
};

type VerifyResponseParams = Pick<
  CompletionExampleParams,
  'client' | 'attestations'
> & {
  readonly completionId: string;
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
};

await main();
