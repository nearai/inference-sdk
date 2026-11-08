import type { SigningAlgo } from '@nearai/inference-sdk/node';
// Experimental Direct endpoint example.
import {
  createPinnedTlsFetch,
  DirectAttestationClient,
  NO_ALIASING_HEADER,
  type VerifiedDirectModelAttestation,
  verifyDirectModelAttestations,
  verifyDirectModelResponse,
} from '@nearai/inference-sdk/node';
import { readChatOutput } from '../utils/chat-output.ts';

// Standalone verification of plaintext Chat bodies over HTTPS.
// See chat-completions.ts for E2EE.
const API_KEY = process.env.NEARAI_API_KEY;
const BASE_URL = `${(
  process.env.NEARAI_BASE_URL ?? 'https://glm-5-3-flash.completions.near.ai/v1/'
).replace(/\/+$/, '')}/`;
const MODEL = process.env.NEARAI_MODEL ?? 'z-ai/glm-5.3-flash';
const SIGNING_ALGO = (process.env.NEARAI_SIGNING_ALGO ??
  'ed25519') as SigningAlgo;

async function main(): Promise<void> {
  if (!API_KEY) throw new Error('NEARAI_API_KEY is required');

  const bootstrapClient = new DirectAttestationClient({
    apiKey: API_KEY,
    baseUrl: BASE_URL,
  });
  const fetched = await bootstrapClient.fetchModelAttestations({
    signingAlgo: SIGNING_ALGO,
  });
  const verified = await verifyDirectModelAttestations(fetched);
  const pinnedTlsFetch = createPinnedTlsFetch(verified.spkiFingerprints);
  const client = new DirectAttestationClient({
    apiKey: API_KEY,
    baseUrl: BASE_URL,
    fetch: pinnedTlsFetch,
  });
  console.log(
    `Verified ${verified.attestations.length} direct model attestations.`,
  );

  const params: CompletionExampleParams = {
    apiKey: API_KEY,
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

  await verifyResponse({
    ...params,
    completionId: completion.id,
    requestBody,
    responseBody,
  });
  console.log(completion.choices[0]?.message.content ?? '');
}

async function runStreamingExample(
  params: CompletionExampleParams,
): Promise<void> {
  const { requestBody, response } = await sendChatRequest({
    ...params,
    stream: true,
  });
  const [responseBytes, { id: completionId }] = await Promise.all([
    response.clone().arrayBuffer(),
    readChatOutput(response, true),
  ]);
  const responseBody = new Uint8Array(responseBytes);
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
    max_completion_tokens: 1024,
    stream,
  });
  const requestBody = new TextEncoder().encode(body);
  const response = await pinnedTlsFetch(new URL('chat/completions', BASE_URL), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'Accept-Encoding': 'identity',
      [NO_ALIASING_HEADER]: 'true',
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

type CompletionExampleParams = {
  readonly apiKey: string;
  readonly client: DirectAttestationClient;
  readonly pinnedTlsFetch: typeof fetch;
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
