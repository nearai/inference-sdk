import { Buffer } from 'node:buffer';
import ed2curve from 'ed2curve';
import nacl from 'tweetnacl';
import {
  NearAiSecureClient,
  SecureClient,
  type QuoteVerificationResult,
  type SecureClientOptions,
} from '../src';
import { decryptE2eeText, encryptE2eeText } from '../src/core/e2ee';
import { appCompose, createGatewayTlsQuote } from './fixtures';

const baseUrl = 'https://gateway.test/v1/';
const model = 'glm-5.2';
const bearerToken = 'aggregator-token';
const eventLog = [
  {
    digest: '00'.repeat(48),
    imr: 3,
    event_type: 0,
    event: 'compose-hash',
    event_payload: 'beef',
  },
];

type CompletionRequest = {
  readonly body: Record<string, unknown>;
  readonly headers: Headers;
};

type TestGatewayState = {
  completionRequests: number;
  gatewayAttestationRequests: number;
  modelAttestationRequests: number;
  readonly completionRequestsSeen: CompletionRequest[];
  readonly decryptedRequestContent: string[];
  readonly decryptedRequestReasoningContent: string[];
  readonly decryptedRequestReasoning: string[];
  readonly decryptedRequestAudio: string[];
  decryptedTool?: {
    readonly name: string;
    readonly description?: string;
    readonly parameters: string;
  };
  decryptedNamedToolChoice?: string;
  readonly decryptedInputToolCalls: Array<{
    readonly name: string;
    readonly arguments: string;
  }>;
};

type TestGateway = {
  readonly fetch: typeof globalThis.fetch;
  readonly quoteVerifier: (quote: string) => QuoteVerificationResult;
  readonly state: TestGatewayState;
};

type CreateTestGatewayParams = {
  readonly includeModelPublicKey?: boolean;
  readonly includeNullableResponseFields?: boolean;
  readonly includeSecondModelAttestation?: boolean;
  readonly encryptedRefusal?: string;
};

type RequestedTool = {
  readonly type?: string;
  readonly function?: {
    readonly name: string;
    readonly description?: string;
    readonly parameters: string;
  };
};

type RequestedMessage = {
  readonly content?: unknown;
  readonly reasoning_content?: string;
  readonly reasoning?: string;
  readonly audio?: { readonly data?: string };
  readonly tool_calls?: readonly RequestedFunctionToolCall[];
};

type RequestedFunctionToolCall = {
  readonly function?: {
    readonly name: string;
    readonly arguments: string;
  };
};

type RequestedToolChoice = {
  readonly type?: string;
  readonly function?: { readonly name: string };
};

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: { 'content-type': 'application/json' },
  });
}

function keyPair(seed: number): nacl.SignKeyPair {
  return nacl.sign.keyPair.fromSeed(Buffer.alloc(32, seed));
}

function keyHex(key: Uint8Array): string {
  return Buffer.from(key).toString('hex');
}

function streamResponse(events: readonly string[]): Response {
  const encoder = new TextEncoder();
  let index = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      const event = events[index];
      index += 1;
      if (event === undefined) {
        controller.close();
        return;
      }
      controller.enqueue(encoder.encode(event));
    },
  });
  return new Response(body, {
    headers: { 'content-type': 'text/event-stream' },
  });
}

function createTestGateway({
  includeModelPublicKey = true,
  includeNullableResponseFields = false,
  includeSecondModelAttestation = false,
  encryptedRefusal,
}: CreateTestGatewayParams = {}): TestGateway {
  const gatewayKeyPair = keyPair(1);
  const modelKeyPair = keyPair(2);
  const secondModelKeyPair = keyPair(3);
  const modelX25519SecretKey = ed2curve.convertSecretKey(
    modelKeyPair.secretKey,
  );
  if (modelX25519SecretKey === null) {
    throw new Error('Failed to create the test model X25519 key');
  }

  const quotes = new Map<string, QuoteVerificationResult>();
  const state: TestGatewayState = {
    completionRequests: 0,
    gatewayAttestationRequests: 0,
    modelAttestationRequests: 0,
    completionRequestsSeen: [],
    decryptedRequestContent: [],
    decryptedRequestReasoningContent: [],
    decryptedRequestReasoning: [],
    decryptedRequestAudio: [],
    decryptedInputToolCalls: [],
  };

  function createAttestation(
    nonce: string,
    signingKeyPair: nacl.SignKeyPair,
    includePublicKey: boolean,
  ) {
    const quoteId = `${keyHex(signingKeyPair.publicKey)}:${nonce}`;
    const quote = createGatewayTlsQuote({
      reportData: Buffer.concat([
        Buffer.from(signingKeyPair.publicKey),
        Buffer.from(nonce, 'hex'),
      ]),
    });
    quotes.set(quoteId, quote);
    return {
      request_nonce: nonce,
      signing_algo: 'ed25519',
      signing_address: keyHex(signingKeyPair.publicKey),
      ...(includePublicKey
        ? { signing_public_key: keyHex(signingKeyPair.publicKey) }
        : {}),
      intel_quote: quoteId,
      event_log: eventLog,
      info: { tcb_info: { app_compose: appCompose } },
      report_data: quote.reportData.toString('hex'),
    };
  }

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);

    if (url.pathname === '/v1/attestation/report') {
      const nonce = url.searchParams.get('nonce');
      if (nonce === null) {
        throw new Error('Expected an attestation nonce');
      }
      expect(request.headers.get('authorization')).toBe(
        `Bearer ${bearerToken}`,
      );
      if (url.searchParams.has('model')) {
        state.modelAttestationRequests += 1;
        return jsonResponse({
          model_attestations: [
            createAttestation(nonce, modelKeyPair, includeModelPublicKey),
            ...(includeSecondModelAttestation
              ? [
                  createAttestation(
                    nonce,
                    secondModelKeyPair,
                    includeModelPublicKey,
                  ),
                ]
              : []),
          ],
        });
      }
      state.gatewayAttestationRequests += 1;
      return jsonResponse({
        gateway_attestation: createAttestation(nonce, gatewayKeyPair, false),
      });
    }

    if (url.pathname !== '/v1/chat/completions') {
      throw new Error(`Unexpected request: ${request.method} ${url.pathname}`);
    }

    state.completionRequests += 1;
    const body = JSON.parse(await request.text()) as Record<string, unknown>;
    state.completionRequestsSeen.push({ body, headers: request.headers });

    const clientPublicKey = request.headers.get('x-client-pub-key');
    if (clientPublicKey === null) {
      return jsonResponse({
        id: 'chatcmpl-plaintext',
        object: 'chat.completion',
        created: 0,
        model,
        choices: [
          {
            index: 0,
            message: { role: 'assistant', content: 'plaintext response' },
            finish_reason: 'stop',
          },
        ],
      });
    }

    const messages = body.messages as RequestedMessage[];
    for (const [index, message] of messages.entries()) {
      if (typeof message.content === 'string') {
        state.decryptedRequestContent.push(
          decryptE2eeText({
            ciphertext: message.content,
            recipientSecretKey: modelX25519SecretKey,
            field: `messages[${index}].content`,
          }),
        );
      }
      if (typeof message.reasoning_content === 'string') {
        state.decryptedRequestReasoningContent.push(
          decryptE2eeText({
            ciphertext: message.reasoning_content,
            recipientSecretKey: modelX25519SecretKey,
            field: `messages[${index}].reasoning_content`,
          }),
        );
      }
      if (typeof message.reasoning === 'string') {
        state.decryptedRequestReasoning.push(
          decryptE2eeText({
            ciphertext: message.reasoning,
            recipientSecretKey: modelX25519SecretKey,
            field: `messages[${index}].reasoning`,
          }),
        );
      }
      if (typeof message.audio?.data === 'string') {
        state.decryptedRequestAudio.push(
          decryptE2eeText({
            ciphertext: message.audio.data,
            recipientSecretKey: modelX25519SecretKey,
            field: `messages[${index}].audio.data`,
          }),
        );
      }
      for (const toolCall of message.tool_calls ?? []) {
        if (toolCall.function === undefined) {
          continue;
        }
        state.decryptedInputToolCalls.push({
          name: decryptE2eeText({
            ciphertext: toolCall.function.name,
            recipientSecretKey: modelX25519SecretKey,
            field: `messages[${index}].tool_calls.function.name`,
          }),
          arguments: decryptE2eeText({
            ciphertext: toolCall.function.arguments,
            recipientSecretKey: modelX25519SecretKey,
            field: `messages[${index}].tool_calls.function.arguments`,
          }),
        });
      }
    }

    const requestedTools = body.tools as RequestedTool[] | undefined;
    const functionTool = requestedTools?.find(
      (tool) => tool.type === 'function',
    )?.function;
    const usesWebContextSearch =
      requestedTools?.some((tool) => tool.type === 'web_context_search') ??
      false;
    if (functionTool !== undefined) {
      state.decryptedTool = {
        name: decryptE2eeText({
          ciphertext: functionTool.name,
          recipientSecretKey: modelX25519SecretKey,
          field: 'tools[0].function.name',
        }),
        ...(functionTool.description === undefined
          ? {}
          : {
              description: decryptE2eeText({
                ciphertext: functionTool.description,
                recipientSecretKey: modelX25519SecretKey,
                field: 'tools[0].function.description',
              }),
            }),
        parameters: decryptE2eeText({
          ciphertext: functionTool.parameters,
          recipientSecretKey: modelX25519SecretKey,
          field: 'tools[0].function.parameters',
        }),
      };
    }

    const requestedToolChoice = body.tool_choice as
      | RequestedToolChoice
      | undefined;
    if (
      requestedToolChoice?.type === 'function' &&
      requestedToolChoice.function !== undefined
    ) {
      state.decryptedNamedToolChoice = decryptE2eeText({
        ciphertext: requestedToolChoice.function.name,
        recipientSecretKey: modelX25519SecretKey,
        field: 'tool_choice.function.name',
      });
    }

    if (body.stream === true) {
      if (usesWebContextSearch) {
        const toolCallChunk = {
          id: 'chatcmpl-web-context-search',
          object: 'chat.completion.chunk',
          created: 0,
          model,
          choices: [
            {
              index: 0,
              delta: {
                tool_calls: [
                  {
                    index: 0,
                    id: 'call_search',
                    type: 'function',
                    function: {
                      name: encryptE2eeText({
                        plaintext: 'web_context_search',
                        recipientPublicKey: clientPublicKey,
                      }),
                      arguments: encryptE2eeText({
                        plaintext: '{"query":"NEAR AI"}',
                        recipientPublicKey: clientPublicKey,
                      }),
                    },
                  },
                ],
              },
              finish_reason: null,
            },
          ],
        };
        const toolResultChunk = {
          id: 'chatcmpl-web-context-search',
          object: 'chat.completion.chunk',
          created: 0,
          model,
          choices: [
            {
              index: 0,
              delta: {
                nearai_tool_result: {
                  tool_call_id: 'call_search',
                  name: 'web_context_search',
                  status: 'completed',
                  output: encryptE2eeText({
                    plaintext: 'NEAR AI search result',
                    recipientPublicKey: clientPublicKey,
                  }),
                },
              },
              finish_reason: null,
            },
          ],
        };
        return streamResponse([
          `data: ${JSON.stringify(toolCallChunk)}\n\n`,
          `data: ${JSON.stringify(toolResultChunk)}\n\n`,
          'data: [DONE]\n\n',
        ]);
      }
      if (functionTool !== undefined) {
        const toolCallChunk = {
          id: 'chatcmpl-tool-stream',
          object: 'chat.completion.chunk',
          created: 0,
          model,
          choices: [
            {
              index: 0,
              delta: {
                tool_calls: [
                  {
                    index: 0,
                    id: 'call_1',
                    type: 'function',
                    function: {
                      name: encryptE2eeText({
                        plaintext: 'weather',
                        recipientPublicKey: clientPublicKey,
                      }),
                      arguments: encryptE2eeText({
                        plaintext: '{"city":"Shanghai"}',
                        recipientPublicKey: clientPublicKey,
                      }),
                    },
                  },
                ],
              },
              finish_reason: 'tool_calls',
            },
          ],
        };
        return streamResponse([
          `data: ${JSON.stringify(toolCallChunk)}\n\n`,
          'data: [DONE]\n\n',
        ]);
      }
      const firstChunk = {
        id: 'chatcmpl-stream',
        object: 'chat.completion.chunk',
        created: 0,
        model,
        choices: [
          {
            index: 0,
            delta: {
              content: encryptE2eeText({
                plaintext: 'hello ',
                recipientPublicKey: clientPublicKey,
              }),
            },
            finish_reason: null,
          },
        ],
      };
      const secondChunk = {
        id: 'chatcmpl-stream',
        object: 'chat.completion.chunk',
        created: 0,
        model,
        choices: [
          {
            index: 0,
            delta: {
              content: encryptE2eeText({
                plaintext: 'client',
                recipientPublicKey: clientPublicKey,
              }),
            },
            finish_reason: 'stop',
          },
        ],
      };
      const firstEvent = `data: ${JSON.stringify(firstChunk)}\n\n`;
      return streamResponse([
        firstEvent.slice(0, 19),
        firstEvent.slice(19),
        `data: ${JSON.stringify(secondChunk)}\n\n`,
        'data: [DONE]\n\n',
      ]);
    }

    const message =
      functionTool === undefined
        ? {
            role: 'assistant',
            content: encryptE2eeText({
              plaintext: 'hello client',
              recipientPublicKey: clientPublicKey,
            }),
          }
        : {
            role: 'assistant',
            content: null,
            tool_calls: [
              {
                id: 'call_1',
                type: 'function',
                function: {
                  name: encryptE2eeText({
                    plaintext: 'weather',
                    recipientPublicKey: clientPublicKey,
                  }),
                  arguments: encryptE2eeText({
                    plaintext: '{"city":"Shanghai"}',
                    recipientPublicKey: clientPublicKey,
                  }),
                },
              },
            ],
          };
    const responseMessage = {
      ...message,
      ...(includeNullableResponseFields
        ? {
            audio: null,
            function_call: null,
            refusal: null,
            tool_calls: [],
          }
        : {}),
      ...(encryptedRefusal === undefined
        ? {}
        : {
            refusal: encryptE2eeText({
              plaintext: encryptedRefusal,
              recipientPublicKey: clientPublicKey,
            }),
          }),
    };
    return jsonResponse({
      id: 'chatcmpl-test',
      object: 'chat.completion',
      created: 0,
      model,
      choices: [
        {
          index: 0,
          message: responseMessage,
          finish_reason: 'stop',
          ...(includeNullableResponseFields ? { logprobs: null } : {}),
        },
      ],
    });
  };

  return {
    fetch,
    quoteVerifier(quote: string): QuoteVerificationResult {
      const result = quotes.get(quote);
      if (result === undefined) {
        throw new Error(`Unknown quote: ${quote}`);
      }
      return result;
    },
    state,
  };
}

function secureClientOptions(gateway: TestGateway): SecureClientOptions {
  return {
    baseUrl,
    bearerToken,
    model,
    gatewayVerification: { verifiers: { quote: gateway.quoteVerifier } },
    modelVerification: { verifiers: { quote: gateway.quoteVerifier } },
  };
}

function chatRequest(body: Record<string, unknown>): RequestInit {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model, ...body }),
  };
}

function isChatCompletionRequest(input: RequestInfo | URL): boolean {
  const url = input instanceof Request ? input.url : input.toString();
  return new URL(url).pathname === '/v1/chat/completions';
}

describe('secure client', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('verify performs one standalone attestation check', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    const session = await client.verify();

    expect(session).toMatchObject({
      model,
      modelSigningPublicKey: expect.any(String),
      modelDeploymentProvenance: 'not_checked',
    });
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 0,
    });
  });

  test('accepts an API key for a direct Gateway connection', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient({
      apiKey: bearerToken,
      baseUrl,
      model,
      gatewayVerification: { verifiers: { quote: gateway.quoteVerifier } },
      modelVerification: { verifiers: { quote: gateway.quoteVerifier } },
    });

    await client.verify();

    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 0,
    });
  });

  test('fetch obtains fresh evidence after a manual verify', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    await client.verify();
    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [{ message: { content: 'hello client' } }],
    });
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 2,
      modelAttestationRequests: 2,
      completionRequests: 1,
    });
  });

  test('blocks an E2EE request when model evidence has no signing public key', async () => {
    const gateway = createTestGateway({ includeModelPublicKey: false });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    await expect(
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      ),
    ).rejects.toMatchObject({
      failure: { code: 'e2ee.model_public_key_required' },
    });
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 0,
    });
  });

  test('fetch verifies, encrypts, and decrypts a Chat Completions request', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [{ message: { content: 'hello client' } }],
    });
    expect(gateway.state.decryptedRequestContent).toEqual(['hello model']);
    expect(
      gateway.state.completionRequestsSeen[0].headers.get('x-model-pub-key'),
    ).toEqual(expect.any(String));
  });

  test('encrypts assistant context fields when present', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [
          { role: 'user', content: 'Continue the prior conversation.' },
          {
            role: 'assistant',
            content: null,
            reasoning_content: 'A private intermediate explanation.',
            reasoning: 'A private reasoning summary.',
            audio: { format: 'wav', data: 'private audio bytes' },
          },
        ],
      }),
    );

    expect(gateway.state.decryptedRequestReasoningContent).toEqual([
      'A private intermediate explanation.',
    ]);
    expect(gateway.state.decryptedRequestReasoning).toEqual([
      'A private reasoning summary.',
    ]);
    expect(gateway.state.decryptedRequestAudio).toEqual([
      'private audio bytes',
    ]);
  });

  test('replaces a caller content length after encrypting the request body', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));
    const request = new Request(`${baseUrl}chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': '1',
      },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: 'hello model' }],
      }),
    });

    await client.fetch(request);

    expect(
      gateway.state.completionRequestsSeen[0].headers.get('content-length'),
    ).toBeNull();
  });

  test('selects a verified model key when multiple candidates are returned', async () => {
    const gateway = createTestGateway({ includeSecondModelAttestation: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [{ message: { content: 'hello client' } }],
    });
    expect(gateway.state.decryptedRequestContent).toEqual(['hello model']);
  });

  test('decrypts a Chat Completions stream split across transport chunks', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new NearAiSecureClient(secureClientOptions(gateway));

    const stream = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello model' }],
      stream: true,
    });
    let content = '';
    for await (const chunk of stream) {
      content += chunk.choices[0]?.delta.content ?? '';
    }

    expect(content).toBe('hello client');
  });

  test('supports a non-streaming OpenAI-compatible chat call', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new NearAiSecureClient(secureClientOptions(gateway));

    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello model' }],
    });

    expect(completion.choices[0]?.message.content).toBe('hello client');
    expect(gateway.state.decryptedRequestContent).toEqual(['hello model']);
  });

  test('accepts nullable and empty Chat response fields under E2EE', async () => {
    const gateway = createTestGateway({ includeNullableResponseFields: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: {
            content: 'hello client',
            audio: null,
            function_call: null,
            refusal: null,
            tool_calls: [],
          },
          logprobs: null,
        },
      ],
    });
  });

  test('decrypts rich response text and audio without rewriting other parts', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (!isChatCompletionRequest(input)) {
        return gateway.fetch(input, init);
      }
      const request = new Request(input, init);
      const clientPublicKey = request.headers.get('x-client-pub-key');
      if (clientPublicKey === null) {
        throw new Error('Expected an E2EE client key');
      }
      return jsonResponse({
        id: 'chatcmpl-rich-response',
        choices: [
          {
            message: {
              role: 'assistant',
              content: [
                {
                  type: 'text',
                  text: encryptE2eeText({
                    plaintext: 'The image shows a lighthouse.',
                    recipientPublicKey: clientPublicKey,
                  }),
                },
                {
                  type: 'image_url',
                  image_url: { url: 'https://example.test/result.png' },
                },
              ],
              audio: {
                format: 'wav',
                data: encryptE2eeText({
                  plaintext: 'audio bytes',
                  recipientPublicKey: clientPublicKey,
                }),
              },
              provider_metadata: { cache_hit: true },
            },
          },
        ],
      });
    });
    const client = new SecureClient(secureClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'describe this' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: {
            content: [
              { type: 'text', text: 'The image shows a lighthouse.' },
              {
                type: 'image_url',
                image_url: { url: 'https://example.test/result.png' },
              },
            ],
            audio: { format: 'wav', data: 'audio bytes' },
            provider_metadata: { cache_hit: true },
          },
        },
      ],
    });
  });

  test('decrypts all-fields logprobs', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (!isChatCompletionRequest(input)) {
        return gateway.fetch(input, init);
      }
      const request = new Request(input, init);
      const clientPublicKey = request.headers.get('x-client-pub-key');
      if (clientPublicKey === null) {
        throw new Error('Expected an E2EE client key');
      }
      return jsonResponse({
        id: 'chatcmpl-logprobs',
        choices: [
          {
            message: {
              role: 'assistant',
              content: encryptE2eeText({
                plaintext: 'Hello',
                recipientPublicKey: clientPublicKey,
              }),
            },
            logprobs: {
              content: [
                {
                  token: encryptE2eeText({
                    plaintext: 'Hello',
                    recipientPublicKey: clientPublicKey,
                  }),
                  bytes: encryptE2eeText({
                    plaintext: JSON.stringify([72, 101, 108, 108, 111]),
                    recipientPublicKey: clientPublicKey,
                  }),
                  top_logprobs: [
                    {
                      token: encryptE2eeText({
                        plaintext: 'Hi',
                        recipientPublicKey: clientPublicKey,
                      }),
                      bytes: encryptE2eeText({
                        plaintext: JSON.stringify([72, 105]),
                        recipientPublicKey: clientPublicKey,
                      }),
                    },
                  ],
                },
              ],
              refusal: [
                {
                  token: encryptE2eeText({
                    plaintext: 'No',
                    recipientPublicKey: clientPublicKey,
                  }),
                  bytes: encryptE2eeText({
                    plaintext: JSON.stringify([78, 111]),
                    recipientPublicKey: clientPublicKey,
                  }),
                },
              ],
            },
          },
        ],
      });
    });
    const client = new SecureClient(secureClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'Say hello.' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: { content: 'Hello' },
          logprobs: {
            content: [
              {
                token: 'Hello',
                bytes: [72, 101, 108, 108, 111],
                top_logprobs: [{ token: 'Hi', bytes: [72, 105] }],
              },
            ],
            refusal: [{ token: 'No', bytes: [78, 111] }],
          },
        },
      ],
    });
  });

  test('uses all-fields E2EE for standard function tools', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [{ role: 'user', content: 'check the weather' }],
        tools: [
          {
            type: 'function',
            function: {
              name: 'weather',
              description: 'Look up the current weather.',
              parameters: {
                type: 'object',
                properties: { city: { type: 'string' } },
              },
            },
          },
        ],
      }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: {
            tool_calls: [
              {
                function: { name: 'weather', arguments: '{"city":"Shanghai"}' },
              },
            ],
          },
        },
      ],
    });
    expect(gateway.state.decryptedTool).toEqual({
      name: 'weather',
      description: 'Look up the current weather.',
      parameters: JSON.stringify({
        type: 'object',
        properties: { city: { type: 'string' } },
      }),
    });
    expect(
      gateway.state.completionRequestsSeen[0].headers.get(
        'x-encrypt-all-fields',
      ),
    ).toBe('true');
  });

  test('preserves response fields the SDK does not transform', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (!isChatCompletionRequest(input)) {
        return gateway.fetch(input, init);
      }
      return jsonResponse({
        id: 'chatcmpl-tool-result',
        choices: [
          {
            message: {
              role: 'assistant',
              content: null,
              audio: { format: 'mp3', data: null },
              tool_calls: [
                {
                  type: 'function',
                  function: { name: null, arguments: null },
                },
              ],
              function_call: { name: null, arguments: null },
            },
            logprobs: { content: [] },
          },
        ],
      });
    });
    const client = new SecureClient(secureClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [{ role: 'user', content: 'check the weather' }],
        tools: [
          {
            type: 'function',
            function: { name: 'weather', parameters: { type: 'object' } },
          },
        ],
      }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: {
            audio: { format: 'mp3', data: null },
            tool_calls: [{ function: { name: null, arguments: null } }],
            function_call: { name: null, arguments: null },
          },
          logprobs: { content: [] },
        },
      ],
    });
  });

  test('encrypts a tool continuation and decrypts all-fields response values', async () => {
    const gateway = createTestGateway({
      encryptedRefusal: 'I cannot provide that information.',
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [
          { role: 'user', content: 'What is the weather in Shanghai?' },
          {
            role: 'assistant',
            content: null,
            tool_calls: [
              {
                id: 'call_1',
                type: 'function',
                function: {
                  name: 'weather',
                  arguments: '{"city":"Shanghai"}',
                },
              },
            ],
          },
          {
            role: 'tool',
            tool_call_id: 'call_1',
            content: '22 C and clear.',
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: 'weather',
              parameters: { type: 'object' },
            },
          },
        ],
        tool_choice: { type: 'function', function: { name: 'weather' } },
      }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [
        {
          message: {
            refusal: 'I cannot provide that information.',
            tool_calls: [
              {
                function: { name: 'weather', arguments: '{"city":"Shanghai"}' },
              },
            ],
          },
        },
      ],
    });
    expect(gateway.state.decryptedRequestContent).toEqual([
      'What is the weather in Shanghai?',
      '22 C and clear.',
    ]);
    expect(gateway.state.decryptedInputToolCalls).toEqual([
      { name: 'weather', arguments: '{"city":"Shanghai"}' },
    ]);
    expect(gateway.state.decryptedNamedToolChoice).toBe('weather');
  });

  test('decrypts standard function tool calls in a Chat Completions stream', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new NearAiSecureClient(secureClientOptions(gateway));

    const stream = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'check the weather' }],
      stream: true,
      tools: [
        {
          type: 'function',
          function: {
            name: 'weather',
            description: 'Look up the current weather.',
            parameters: { type: 'object' },
          },
        },
      ],
    });
    const toolCalls: Array<{ name?: string; arguments?: string }> = [];
    for await (const chunk of stream) {
      for (const toolCall of chunk.choices[0]?.delta.tool_calls ?? []) {
        toolCalls.push({
          name: toolCall.function?.name,
          arguments: toolCall.function?.arguments,
        });
      }
    }

    expect(toolCalls).toEqual([
      { name: 'weather', arguments: '{"city":"Shanghai"}' },
    ]);
    expect(
      gateway.state.completionRequestsSeen[0].headers.get(
        'x-encrypt-all-fields',
      ),
    ).toBe('true');
  });

  test('supports an encrypted web_context_search stream', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [{ role: 'user', content: 'Search for NEAR AI.' }],
        stream: true,
        tools: [{ type: 'web_context_search' }],
      }),
    );
    const stream = await response.text();

    expect(stream).toContain('"name":"web_context_search"');
    expect(stream).toContain('"arguments":"{\\"query\\":\\"NEAR AI\\"}"');
    expect(stream).toContain('"output":"NEAR AI search result"');
    expect(
      gateway.state.completionRequestsSeen[0].headers.get(
        'x-encrypt-all-fields',
      ),
    ).toBe('true');
    expect(gateway.state.completionRequestsSeen[0].body.tools).toEqual([
      { type: 'web_context_search' },
    ]);
  });

  test('leaves web_context_search request acceptance to the Gateway', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [{ role: 'user', content: 'Search for NEAR AI.' }],
        tools: [{ type: 'web_context_search' }],
      }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [{ message: { content: 'hello client' } }],
    });
    expect(gateway.state.completionRequests).toBe(1);
  });

  test('fails closed when an encrypted Chat response is tampered with', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const response = await gateway.fetch(input, init);
      if (!isChatCompletionRequest(input)) {
        return response;
      }
      return jsonResponse({
        id: 'chatcmpl-tampered',
        choices: [
          {
            message: {
              role: 'assistant',
              content: 'not-a-valid-ciphertext',
            },
          },
        ],
      });
    });
    const client = new SecureClient(secureClientOptions(gateway));

    await expect(
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      ),
    ).rejects.toMatchObject({
      failure: {
        code: 'e2ee.decryption_failed',
        details: { field: 'choices[0].message.content' },
      },
    });
    expect(gateway.state.completionRequests).toBe(1);
  });

  test('returns non-success Chat responses without decrypting them', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (!isChatCompletionRequest(input)) {
        return gateway.fetch(input, init);
      }
      return new Response(JSON.stringify({ error: { message: 'try later' } }), {
        status: 503,
        headers: { 'content-type': 'application/json' },
      });
    });
    const client = new SecureClient(secureClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: { message: 'try later' },
    });
  });

  test('keeps verification and model routing on when E2EE is disabled', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient({
      ...secureClientOptions(gateway),
      e2ee: false,
    });
    const richContent = [{ type: 'text', text: 'plain Chat payload' }];

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: richContent }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [{ message: { content: 'plaintext response' } }],
    });
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 1,
    });
    const request = gateway.state.completionRequestsSeen[0];
    expect(request.body.messages).toEqual([
      { role: 'user', content: richContent },
    ]);
    expect(request.headers.get('x-client-pub-key')).toBeNull();
    expect(request.headers.get('x-model-pub-key')).toEqual(expect.any(String));
  });

  test('does not send a completion when a deployment policy rejects it', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient({
      ...secureClientOptions(gateway),
      deploymentPolicy: () => {
        throw new Error('deployment is not approved');
      },
    });

    await expect(
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      ),
    ).rejects.toMatchObject({
      failure: { code: 'provenance.verification_failed' },
    });
    expect(gateway.state.completionRequests).toBe(0);
  });

  test('does not send a completion when model verification fails', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient({
      ...secureClientOptions(gateway),
      modelVerification: {
        verifiers: {
          quote: () => {
            throw new Error('model quote rejected');
          },
        },
      },
    });

    await expect(
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      ),
    ).rejects.toMatchObject({
      failure: { code: 'quote.verification_failed' },
    });
    expect(gateway.state.completionRequests).toBe(0);
  });

  test('encrypts rich content and forwards other Chat fields to the Gateway', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));
    const richContent = [
      { type: 'text', text: 'describe this image' },
      {
        type: 'image_url',
        image_url: { url: 'https://example.test/image.png' },
      },
    ];

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [
          {
            role: 'user',
            content: richContent,
            provider_message_option: { detail: 'high' },
          },
        ],
        response_format: { type: 'json_object' },
        provider_request_option: { priority: 'normal' },
        tools: [{ type: 'provider_extension', setting: 'enabled' }],
      }),
    );

    expect(JSON.parse(gateway.state.decryptedRequestContent[0] ?? '')).toEqual(
      richContent,
    );
    expect(gateway.state.completionRequestsSeen[0]?.body).toMatchObject({
      response_format: { type: 'json_object' },
      provider_request_option: { priority: 'normal' },
      tools: [{ type: 'provider_extension', setting: 'enabled' }],
      messages: [
        {
          provider_message_option: { detail: 'high' },
        },
      ],
    });
    expect(
      gateway.state.completionRequestsSeen[0]?.headers.get(
        'x-encrypt-all-fields',
      ),
    ).toBe('true');
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 1,
    });
  });

  test('rejects non-Chat paths before it fetches attestation evidence', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new SecureClient(secureClientOptions(gateway));

    await expect(
      client.fetch(
        `${baseUrl}responses`,
        chatRequest({ input: 'hello model' }),
      ),
    ).rejects.toMatchObject({
      failure: { code: 'api.invalid_input', details: { field: 'request' } },
    });
    expect(gateway.state.gatewayAttestationRequests).toBe(0);
    expect(gateway.state.modelAttestationRequests).toBe(0);
  });
});
