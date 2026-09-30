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
import { retryRateLimit } from './retry.ts';

type LiveModel = {
  id: string;
  provider: 'near' | 'chutes' | 'external';
};

const BASE_URL = `${requiredEnv('NEARAI_BASE_URL').replace(/\/+$/, '')}/`;
const API_KEY = requiredEnv('NEARAI_API_KEY');
const MODELS: LiveModel[] = JSON.parse(requiredEnv('NEARAI_E2E_MODELS'));
const MODEL = MODELS.find(({ provider }) => provider === 'near')?.id;
assert.ok(MODEL, 'Expected a NEAR model for the E2EE/OHTTP client cases');
const CHAT_REQUEST = {
  model: MODEL,
  messages: [{ role: 'user', content: 'Reply with the single word OK.' }],
  // Reasoning tokens share this budget; leave room for a visible answer.
  max_completion_tokens: 1024,
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

for (const model of MODELS.filter(({ provider }) => provider !== 'near')) {
  test(`Node client handles ${model.provider} Chat: ${model.id}`, {
    timeout: 180_000,
  }, async () => {
    const inferenceClient = new InferenceClient({
      apiKey: API_KEY,
      baseUrl: BASE_URL,
      e2ee: false,
    });
    await inferenceClient.verify(model.id);
    if (model.provider === 'chutes') {
      const completion = await retryRateLimit(() =>
        inferenceClient.chat.completions.create(
          { ...CHAT_REQUEST, model: model.id },
          { maxRetries: 0 },
        ),
      );
      assert.ok(completion.id);
      assert.equal(completion.choices[0]?.finish_reason, 'stop');
      assert.ok(completion.choices[0]?.message.content?.trim());
      const verified = await retryReceipt(() =>
        inferenceClient.verifyResponse(completion.id),
      );
      assert.equal(verified.signature.kind, 'gateway');
    } else {
      await verifyClientCompletions({
        inferenceClient,
        chat: inferenceClient.chat,
        model: model.id,
        expectedSignatureKind: 'gateway',
      });
    }
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
  model?: string;
  expectedSignatureKind?: 'gateway';
};

async function verifyClientCompletions({
  inferenceClient,
  chat,
  signingAlgo = 'ed25519',
  model = CHAT_REQUEST.model,
  expectedSignatureKind,
}: VerifyClientCompletionsParams): Promise<void> {
  const request = { ...CHAT_REQUEST, model };
  const completion = await retryRateLimit(() =>
    chat.completions.create(request, { maxRetries: 0 }),
  );
  assert.ok(completion.id);
  assert.equal(completion.choices[0]?.finish_reason, 'stop');
  assert.ok(completion.choices[0]?.message.content?.trim());
  const verified = await retryReceipt(() =>
    inferenceClient.verifyResponse(completion.id),
  );
  assert.equal(verified.signature.signer.signingAlgo, signingAlgo);
  if (expectedSignatureKind) {
    assert.equal(verified.signature.kind, expectedSignatureKind);
  }

  const stream = await retryRateLimit(() =>
    chat.completions.create({ ...request, stream: true }, { maxRetries: 0 }),
  );
  let completionId: string | undefined;
  let content = '';
  let finishReason: string | undefined;
  for await (const chunk of stream) {
    if (completionId !== undefined) assert.equal(chunk.id, completionId);
    completionId = chunk.id;
    content += chunk.choices[0]?.delta.content ?? '';
    const reason = chunk.choices[0]?.finish_reason;
    if (reason != null) finishReason = reason;
  }
  assert.ok(completionId, 'SSE must contain a completion ID');
  assert.equal(finishReason, 'stop', 'SSE must complete without truncation');
  assert.ok(content.trim(), 'Expected non-empty Chat content');
  const streamedId = completionId;
  const verifiedStream = await retryReceipt(() =>
    inferenceClient.verifyResponse(streamedId),
  );
  assert.equal(verifiedStream.signature.signer.signingAlgo, signingAlgo);
  if (expectedSignatureKind) {
    assert.equal(verifiedStream.signature.kind, expectedSignatureKind);
  }
}

for (const selectedModel of MODELS) {
  test(`Standalone APIs handle ${selectedModel.provider} Chat: ${selectedModel.id}`, {
    timeout: 180_000,
  }, async () => {
    const client = new AttestationClient({
      apiKey: API_KEY,
      baseUrl: BASE_URL,
    });
    const signingAlgo = 'ed25519';
    const fetchedGateway = await client.fetchGatewayAttestation({
      signingAlgo,
    });
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

    const models = [];
    if (selectedModel.provider === 'near') {
      const fetchedModels = await client.fetchModelAttestations({
        model: selectedModel.id,
        signingAlgo,
      });
      assert.ok(
        fetchedModels.attestations.length > 0,
        'Expected NEAR model evidence',
      );
      for (const attestation of fetchedModels.attestations) {
        const model = await verifyModelAttestation({
          attestation,
          clientBinding: fetchedModels.clientBinding,
          policy: { gpuEvidence: 'required' },
        });
        models.push(model);
      }
    }

    // Chutes returns a Gateway receipt. Streaming is separately provider-gated,
    // so its live case uses JSON only.
    const streams =
      selectedModel.provider === 'chutes' ? [false] : [false, true];
    for (const stream of streams) {
      const requestBody = new TextEncoder().encode(
        JSON.stringify({ ...CHAT_REQUEST, model: selectedModel.id, stream }),
      );
      const response = await retryRateLimit(() =>
        pinnedTlsFetch(new URL('chat/completions', BASE_URL), {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${API_KEY}`,
            'Content-Type': 'application/json',
            'Accept-Encoding': 'identity',
            'x-no-aliasing': 'true',
          },
          body: requestBody,
        }),
      );
      assert.equal(response.status, 200, 'Chat request must succeed');
      const responseBody = new Uint8Array(await response.arrayBuffer());
      const id = readCompletionId({ responseBody, stream });
      const signature = await retryReceipt(() =>
        client.fetchCompletionSignature({ completionId: id, signingAlgo }),
      );
      assert.equal(signature.signer.signingAlgo, signingAlgo);
      if (selectedModel.provider !== 'near') {
        assert.equal(signature.kind, 'gateway');
      }
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
}

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
    assert.equal(completion.choices[0]?.finish_reason, 'stop');
    assert.ok(completion.choices[0]?.message.content?.trim());
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
  let content = '';
  let finishReason: string | undefined;
  for (const chunk of chunks) {
    assert.equal(chunk.id, id);
    const choice = chunk.choices[0];
    content += choice?.delta.content ?? '';
    if (choice?.finish_reason != null) finishReason = choice.finish_reason;
  }
  assert.equal(finishReason, 'stop', 'SSE must complete without truncation');
  assert.ok(content.trim(), 'Expected non-empty Chat content');
  return id;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  assert.ok(value, `${name} is required for live E2E tests`);
  return value;
}
