import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import OpenAI from 'openai';
import {
  InferenceClient as GenericInferenceClient,
  isApiError as isGenericApiError,
} from '../dist/index.js';
import type {
  InferenceChat,
  InferenceClientOptions,
  SigningAlgo,
} from '../dist/node.js';
import {
  AttestationClient,
  createPinnedTlsFetch,
  findModelAttestationForSignature,
  InferenceClient,
  isApiError,
  VerificationError,
  verifyGatewayAttestation,
  verifyGatewayResponse,
  verifyModelAttestation,
  verifyModelResponse,
} from '../dist/node.js';

const BASE_URL = `${requiredEnv('NEARAI_E2E_BASE_URL').replace(/\/+$/, '')}/`;
const API_KEY = requiredEnv('NEARAI_E2E_API_KEY');
const MODEL = process.env.NEARAI_E2E_MODEL || 'z-ai/glm-5.3-flash';
const CHAT_REQUEST = {
  model: MODEL,
  messages: [{ role: 'user', content: 'Reply with the single word OK.' }],
  max_completion_tokens: 128,
} satisfies OpenAI.ChatCompletionCreateParamsNonStreaming;

type ClientCase = {
  name: string;
  options: InferenceClientOptions;
};

const CLIENT_CASES: readonly ClientCase[] = [
  {
    name: 'unencrypted Chat',
    options: { apiKey: API_KEY, baseUrl: BASE_URL, e2ee: false },
  },
  {
    name: 'Ed25519 E2EE',
    options: {
      apiKey: API_KEY,
      baseUrl: BASE_URL,
      e2ee: true,
      signingAlgo: 'ed25519',
    },
  },
  {
    name: 'ECDSA E2EE',
    options: {
      apiKey: API_KEY,
      baseUrl: BASE_URL,
      e2ee: true,
      signingAlgo: 'ecdsa',
    },
  },
  {
    name: 'OHTTP with Ed25519 E2EE',
    options: {
      apiKey: API_KEY,
      baseUrl: BASE_URL,
      e2ee: true,
      ohttp: true,
    },
  },
];

for (const { name, options } of CLIENT_CASES) {
  test(`Node client verifies JSON and SSE with ${name}`, {
    timeout: 180_000,
  }, async () => {
    const inferenceClient = new InferenceClient(options);
    await inferenceClient.verify(MODEL);
    await verifyClientCompletions({
      inferenceClient,
      chat: inferenceClient.chat,
      signingAlgo: options.signingAlgo,
    });
  });
}

test('OpenAI SDK uses the verified fetch transport', {
  timeout: 180_000,
}, async () => {
  const inferenceClient = new InferenceClient({
    apiKey: API_KEY,
    baseUrl: BASE_URL,
    e2ee: true,
  });
  const openai = new OpenAI({
    apiKey: API_KEY,
    baseURL: BASE_URL,
    fetch: inferenceClient.fetch,
    maxRetries: 0,
  });
  await verifyClientCompletions({ inferenceClient, chat: openai.chat });
});

test('Generic entry verifies JSON and SSE without peer TLS binding', {
  timeout: 180_000,
}, async () => {
  // Exercise the browser-compatible entry in Node, not browser networking/CORS.
  const inferenceClient = new GenericInferenceClient({
    apiKey: API_KEY,
    baseUrl: BASE_URL,
    e2ee: true,
  });
  await verifyClientCompletions({
    inferenceClient,
    chat: inferenceClient.chat,
  });
});

type VerifyClientCompletionsParams = {
  inferenceClient: Pick<InferenceClient, 'verifyResponse'>;
  chat: InferenceChat;
  signingAlgo?: SigningAlgo;
};

async function verifyClientCompletions({
  inferenceClient,
  chat,
  signingAlgo = 'ed25519',
}: VerifyClientCompletionsParams): Promise<void> {
  const completion = await chat.completions.create(CHAT_REQUEST, {
    maxRetries: 0,
  });
  assert.ok(completion.id);
  assert.match(completion.choices[0]?.message.content ?? '', /\bOK\b/i);
  const verified = await retryReceipt(() =>
    inferenceClient.verifyResponse(completion.id),
  );
  assert.equal(verified.signature.signer.signingAlgo, signingAlgo);

  const stream = await chat.completions.create(
    { ...CHAT_REQUEST, stream: true },
    { maxRetries: 0 },
  );
  let completionId: string | undefined;
  let content = '';
  let finished = false;
  for await (const chunk of stream) {
    if (completionId !== undefined) assert.equal(chunk.id, completionId);
    completionId = chunk.id;
    content += chunk.choices[0]?.delta.content ?? '';
    finished ||= chunk.choices.some((choice) => choice.finish_reason !== null);
  }
  assert.ok(completionId, 'SSE must contain a completion ID');
  assert.ok(finished, 'SSE must contain a terminal completion chunk');
  assert.match(content, /\bOK\b/i);
  const streamedId = completionId;
  const verifiedStream = await retryReceipt(() =>
    inferenceClient.verifyResponse(streamedId),
  );
  assert.equal(verifiedStream.signature.signer.signingAlgo, signingAlgo);
}

test('Standalone APIs verify deployments and byte-exact JSON/SSE receipts', {
  timeout: 180_000,
}, async () => {
  const client = new AttestationClient({ apiKey: API_KEY, baseUrl: BASE_URL });
  const signingAlgo = 'ed25519';
  const fetchedGateway = await client.fetchGatewayAttestation({ signingAlgo });
  const gateway = await verifyGatewayAttestation({
    attestation: fetchedGateway.attestation,
    clientBinding: fetchedGateway.clientBinding,
  });
  assert.ok(
    gateway.tlsBinding.kind === 'attested',
    'Expected peer TLS binding',
  );
  const pinnedTlsFetch = createPinnedTlsFetch(
    gateway.tlsBinding.spkiFingerprint,
  );

  const fetchedModels = await client.fetchModelAttestations({
    model: MODEL,
    signingAlgo,
  });
  assert.ok(
    fetchedModels.attestations.length > 0,
    'Expected NEAR model evidence',
  );
  const models = [];
  for (const attestation of fetchedModels.attestations) {
    const model = await verifyModelAttestation({
      attestation,
      clientBinding: fetchedModels.clientBinding,
      policy: { gpuEvidence: 'required' },
    });
    models.push(model);
  }

  for (const stream of [false, true]) {
    const requestBody = new TextEncoder().encode(
      JSON.stringify({ ...CHAT_REQUEST, stream }),
    );
    const response = await pinnedTlsFetch(
      new URL('chat/completions', BASE_URL),
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${API_KEY}`,
          'Content-Type': 'application/json',
          'Accept-Encoding': 'identity',
          'x-no-aliasing': 'true',
        },
        body: requestBody,
      },
    );
    assert.equal(response.status, 200, 'Chat request must succeed');
    const responseBody = new Uint8Array(await response.arrayBuffer());
    const id = readCompletionId({ responseBody, stream });
    const signature = await retryReceipt(() =>
      client.fetchCompletionSignature({ completionId: id, signingAlgo }),
    );
    assert.equal(signature.signer.signingAlgo, signingAlgo);
    // Changing even whitespace must invalidate the receipt's byte binding.
    const altered = new Uint8Array([...responseBody, 0x20]);
    if (signature.kind === 'provider_tee') {
      const attestation = findModelAttestationForSignature({
        attestations: models,
        signature,
      });
      const params = { requestBody, responseBody, signature, attestation };
      verifyModelResponse(params);
      assert.throws(
        () => verifyModelResponse({ ...params, responseBody: altered }),
        VerificationError,
      );
    } else {
      const params = {
        requestBody,
        responseBody,
        signature,
        attestation: gateway,
      };
      verifyGatewayResponse(params);
      assert.throws(
        () => verifyGatewayResponse({ ...params, responseBody: altered }),
        VerificationError,
      );
    }
  }
});

// Allow receipt propagation after Chat, without repeating inference or masking
// cryptographic verification failures. The enclosing test still has a deadline.
async function retryReceipt<T>(lookup: () => Promise<T>): Promise<T> {
  for (const backoffMs of [500, 1_000, 2_000, 4_000]) {
    try {
      return await lookup();
    } catch (error) {
      if (
        !(isApiError(error) || isGenericApiError(error)) ||
        !error.retryable
      ) {
        throw error;
      }
    }
    await delay(backoffMs);
  }
  return lookup();
}

type ReadCompletionIdParams = {
  responseBody: Uint8Array;
  stream: boolean;
};

function readCompletionId({
  responseBody,
  stream,
}: ReadCompletionIdParams): string {
  const text = new TextDecoder().decode(responseBody);
  if (!stream) {
    const completion = JSON.parse(text);
    assert.equal(typeof completion.id, 'string');
    assert.match(completion.choices[0]?.message.content ?? '', /\bOK\b/i);
    return completion.id;
  }

  const events = text
    .split(/\r?\n/)
    .filter((line) => line.startsWith('data:'))
    .map((line) => line.slice(5).trim());
  assert.equal(
    events.at(-1),
    '[DONE]',
    'SSE must finish before receipt verification',
  );
  const chunks = events
    .filter((event) => event !== '[DONE]')
    .map((event) => JSON.parse(event));
  const id = chunks[0]?.id;
  assert.equal(typeof id, 'string');
  assert.ok(chunks.every((chunk) => chunk.id === id));
  const content = chunks
    .map((chunk) => chunk.choices[0]?.delta.content ?? '')
    .join('');
  assert.match(content, /\bOK\b/i);
  return id;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  assert.ok(value, `${name} is required for live E2E tests`);
  return value;
}
