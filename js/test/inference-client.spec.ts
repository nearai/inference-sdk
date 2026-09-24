import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import ed2curve from 'ed2curve';
import OpenAI from 'openai';
import nacl from 'tweetnacl';
import {
  InferenceClient,
  type InferenceClientOptions,
  type TdxQuoteVerificationResult,
} from '../src';
import type { GatewayAttestationHttpResponse } from '../src/core/cloud-api';
import {
  decryptE2eeText as decryptE2eeValue,
  encryptE2eeText as encryptE2eeValue,
} from '../src/core/e2ee';
import {
  AttestationClient as NodeAttestationClient,
  InferenceClient as NodeInferenceClient,
} from '../src/node';
import {
  appCompose,
  createGatewayTlsQuote,
  sha256,
  tlsFingerprint,
} from './fixtures';
import { createOhttpEndpoint } from './ohttp-fixtures';

const baseUrl = 'https://gateway.test/v1/';
const model = 'glm-5.3-flash';
const secondModel = 'qwen-3.5';
const aggregatorHeader = {
  name: 'x-aggregator-token',
  value: 'aggregator-token',
};
const directApiKey = 'direct-api-key';
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
  readonly gatewayAttestationIncludeSpkiFingerprints: boolean[];
  modelAttestationRequests: number;
  readonly modelAttestationModels: string[];
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
  readonly expectRequestHeader: (request: Request) => void;
  readonly createProviderSignature: (
    requestBody: Uint8Array,
    responseBody: Uint8Array,
  ) => Record<string, string>;
  readonly tdxQuoteVerifier: (quote: string) => TdxQuoteVerificationResult;
  readonly state: TestGatewayState;
};

type CreateTestGatewayParams = {
  readonly expectedRequestHeader?: {
    readonly name: string;
    readonly value: string;
  };
  readonly includeModelPublicKey?: boolean;
  readonly includeNullableResponseFields?: boolean;
  readonly includeSecondModelAttestation?: boolean;
  readonly encryptedRefusal?: string;
  readonly streamRecordSeparators?: readonly string[];
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

type EncryptEd25519TextParams = {
  readonly plaintext: string;
  readonly recipientPublicKey: string;
};

function encryptE2eeText({
  plaintext,
  recipientPublicKey,
}: EncryptEd25519TextParams): string {
  return encryptE2eeValue({
    plaintext,
    modelKey: { signingAlgo: 'ed25519', publicKey: recipientPublicKey },
  });
}

type DecryptEd25519TextParams = {
  readonly ciphertext: string;
  readonly recipientSecretKey: Uint8Array;
  readonly field: string;
};

/** The in-memory Gateway fixture implements the Ed25519 v2 model side. */
function decryptE2eeText({
  ciphertext,
  recipientSecretKey,
  field,
}: DecryptEd25519TextParams): string {
  return decryptE2eeValue({
    ciphertext,
    clientKeyPair: {
      signingAlgo: 'ed25519',
      publicKey: '',
      x25519SecretKey: recipientSecretKey,
    },
    field,
  });
}

function hashBytes(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
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
  expectedRequestHeader = aggregatorHeader,
  includeModelPublicKey = true,
  includeNullableResponseFields = false,
  includeSecondModelAttestation = false,
  encryptedRefusal,
  streamRecordSeparators,
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

  const quotes = new Map<string, TdxQuoteVerificationResult>();
  const state: TestGatewayState = {
    completionRequests: 0,
    gatewayAttestationRequests: 0,
    gatewayAttestationIncludeSpkiFingerprints: [],
    modelAttestationRequests: 0,
    modelAttestationModels: [],
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
    gatewaySpkiFingerprint?: string,
  ) {
    const quoteId = `${keyHex(signingKeyPair.publicKey)}:${nonce}`;
    const quote = createGatewayTlsQuote({
      reportData:
        gatewaySpkiFingerprint === undefined
          ? Buffer.concat([
              Buffer.from(signingKeyPair.publicKey),
              Buffer.from(nonce, 'hex'),
            ])
          : Buffer.concat([
              sha256(
                Buffer.concat([
                  Buffer.from(signingKeyPair.publicKey),
                  Buffer.from(gatewaySpkiFingerprint, 'hex'),
                ]),
              ),
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
      ...(gatewaySpkiFingerprint === undefined
        ? {}
        : { tls_cert_fingerprint: gatewaySpkiFingerprint }),
    };
  }

  function expectRequestHeader(request: Request): void {
    expect(request.headers.get(expectedRequestHeader.name)).toBe(
      expectedRequestHeader.value,
    );
  }

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    expectRequestHeader(request);

    if (url.pathname === '/v1/attestation/report') {
      const nonce = url.searchParams.get('nonce');
      if (nonce === null) {
        throw new Error('Expected an attestation nonce');
      }
      if (url.searchParams.has('model')) {
        state.modelAttestationRequests += 1;
        state.modelAttestationModels.push(url.searchParams.get('model') ?? '');
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
      const includeSpkiFingerprint =
        url.searchParams.get('include_tls_fingerprint') === 'true';
      state.gatewayAttestationIncludeSpkiFingerprints.push(
        includeSpkiFingerprint,
      );
      return jsonResponse({
        gateway_attestation: createAttestation(
          nonce,
          gatewayKeyPair,
          false,
          includeSpkiFingerprint ? tlsFingerprint : undefined,
        ),
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
      const separator = (index: number): string =>
        streamRecordSeparators?.[index] ?? '\r\r';
      const firstEvent = `data: {\r\ndata: ${JSON.stringify(firstChunk).slice(1)}${separator(0)}`;
      // Split a CRLF inside the JSON event across transport chunks.
      const split = firstEvent.indexOf('\r\n') + 1;
      return streamResponse([
        firstEvent.slice(0, split),
        firstEvent.slice(split),
        `data: ${JSON.stringify(secondChunk)}${separator(1)}`,
        `data: [DONE]${separator(2)}`,
        `: response complete${separator(3)}`,
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
    expectRequestHeader,
    createProviderSignature(
      requestBody: Uint8Array,
      responseBody: Uint8Array,
    ): Record<string, string> {
      const text = `${model}:${hashBytes(requestBody)}:${hashBytes(responseBody)}`;
      return {
        text,
        signature: keyHex(
          nacl.sign.detached(Buffer.from(text), modelKeyPair.secretKey),
        ),
        signing_address: keyHex(modelKeyPair.publicKey),
        signing_algo: 'ed25519',
        signature_kind: 'provider_tee',
      };
    },
    tdxQuoteVerifier(quote: string): TdxQuoteVerificationResult {
      const result = quotes.get(quote);
      if (result === undefined) {
        throw new Error(`Unknown quote: ${quote}`);
      }
      return result;
    },
    state,
  };
}

function inferenceClientOptions(gateway: TestGateway): InferenceClientOptions {
  return {
    e2ee: true,
    baseUrl,
    headers: { [aggregatorHeader.name]: aggregatorHeader.value },
    gatewayVerification: { verifiers: { tdxQuote: gateway.tdxQuoteVerifier } },
    modelVerification: { verifiers: { tdxQuote: gateway.tdxQuoteVerifier } },
  };
}

type NodeAttestationClientPrototype = {
  requestGatewayAttestation: (
    request: Request,
    capturePeerSpkiFingerprint: boolean,
  ) => Promise<GatewayAttestationHttpResponse>;
};

type MockNodeGatewayAttestationParams = {
  readonly gateway: TestGateway;
  readonly peerSpkiFingerprint?: string;
};

class TestNodeInferenceClient extends NodeInferenceClient {
  readonly pinnedSpkiFingerprints: string[] = [];
  private readonly testPinnedFetch: typeof globalThis.fetch;

  constructor(
    options: InferenceClientOptions,
    testPinnedFetch: typeof globalThis.fetch,
  ) {
    super(options);
    this.testPinnedFetch = testPinnedFetch;
  }

  protected override createPinnedTlsFetch(
    spkiFingerprint: string,
  ): typeof globalThis.fetch {
    this.pinnedSpkiFingerprints.push(spkiFingerprint);
    return this.testPinnedFetch;
  }
}

function mockNodeGatewayAttestation({
  gateway,
  peerSpkiFingerprint = tlsFingerprint,
}: MockNodeGatewayAttestationParams): boolean[] {
  const capturedPeerSpkiFingerprints: boolean[] = [];
  const prototype =
    NodeAttestationClient.prototype as unknown as NodeAttestationClientPrototype;
  jest
    .spyOn(prototype, 'requestGatewayAttestation')
    .mockImplementation(async (request, capturePeerSpkiFingerprint) => {
      capturedPeerSpkiFingerprints.push(capturePeerSpkiFingerprint);
      const response = await gateway.fetch(request);
      return {
        response,
        ...(capturePeerSpkiFingerprint ? { peerSpkiFingerprint } : {}),
      };
    });
  return capturedPeerSpkiFingerprints;
}

function chatRequest(body: Record<string, unknown>): RequestInit {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model, ...body }),
  };
}

function createProviderSignatureFetch(
  gateway: TestGateway,
): typeof globalThis.fetch {
  const signatures = new Map<string, Promise<Record<string, string>>>();
  return async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (url.pathname.startsWith('/v1/signature/')) {
      gateway.expectRequestHeader(request);
      const completionId = url.pathname.slice('/v1/signature/'.length);
      const signature = signatures.get(completionId);
      if (signature === undefined) {
        throw new Error(`No signature for ${completionId}`);
      }
      expect(url.searchParams.get('signing_algo')).toBe('ed25519');
      return jsonResponse(await signature);
    }
    if (url.pathname !== '/v1/chat/completions') {
      return gateway.fetch(request);
    }

    const requestBody = new Uint8Array(await request.clone().arrayBuffer());
    const body = JSON.parse(new TextDecoder().decode(requestBody)) as {
      stream?: boolean;
    };
    const response = await gateway.fetch(request);
    const completionId =
      body.stream === true
        ? 'chatcmpl-stream'
        : (await response.clone().json()).id;
    signatures.set(
      completionId,
      response
        .clone()
        .arrayBuffer()
        .then((responseBody) =>
          gateway.createProviderSignature(
            requestBody,
            new Uint8Array(responseBody),
          ),
        ),
    );
    return response;
  };
}

function mockProviderSignatures(gateway: TestGateway): void {
  jest
    .spyOn(globalThis, 'fetch')
    .mockImplementation(createProviderSignatureFetch(gateway));
}

function isChatCompletionRequest(input: RequestInfo | URL): boolean {
  const url = input instanceof Request ? input.url : input.toString();
  return new URL(url).pathname === '/v1/chat/completions';
}

describe('inference client', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  test('sends the default plaintext OpenAI request byte-for-byte over native fetch', async () => {
    const gateway = createTestGateway();
    const nativeFetch = globalThis.fetch.bind(globalThis);
    let receivedBody = Buffer.alloc(0);
    let receivedLength: string | undefined;
    const server = createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      receivedBody = Buffer.concat(chunks);
      receivedLength = request.headers['content-length'];
      response.setHeader('content-type', 'application/json');
      response.end(
        JSON.stringify({
          id: 'chatcmpl-native-fetch',
          object: 'chat.completion',
          created: 0,
          model,
          choices: [
            {
              index: 0,
              message: { role: 'assistant', content: 'received' },
              finish_reason: 'stop',
            },
          ],
        }),
      );
    });
    await new Promise<void>((resolve) =>
      server.listen(0, '127.0.0.1', resolve),
    );
    try {
      const address = server.address();
      if (address === null || typeof address === 'string')
        throw new Error('Missing local test port');
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation((input, init) =>
          isChatCompletionRequest(input)
            ? nativeFetch(input, init)
            : gateway.fetch(input, init),
        );
      const client = new InferenceClient({
        baseUrl: `http://127.0.0.1:${address.port}/v1/`,
        headers: { [aggregatorHeader.name]: aggregatorHeader.value },
        gatewayVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
        modelVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
      });
      const body = {
        model,
        messages: [{ role: 'user' as const, content: '你好 🌎 — plaintext' }],
      };
      const completion = await client.chat.completions.create(body, {
        maxRetries: 0,
        timeout: 5_000,
      });
      expect(completion.id).toBe('chatcmpl-native-fetch');
      expect(receivedBody).toEqual(Buffer.from(JSON.stringify(body)));
      expect(receivedLength).toBe(String(receivedBody.byteLength));
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });

  test('uses pinned OHTTP for JSON and SSE while retaining evidence, signatures and session reuse', async () => {
    const gateway = createTestGateway();
    const endpoint = await createOhttpEndpoint({
      fetch: createProviderSignatureFetch(gateway),
      signingKey: keyPair(1),
    });
    mockNodeGatewayAttestation({
      gateway: { ...gateway, fetch: endpoint.fetch },
    });
    const pinnedFetch = jest.fn(endpoint.fetch);
    const rawFetch = jest.spyOn(globalThis, 'fetch');
    const client = new TestNodeInferenceClient(
      {
        ...inferenceClientOptions(gateway),
        ohttp: true,
        signingAlgo: 'ed25519',
      },
      pinnedFetch,
    );

    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello JSON' }],
    });
    expect(completion.choices[0].message.content).toBe('hello client');
    await expect(client.verifyResponse(completion.id)).resolves.toMatchObject({
      completionId: completion.id,
      signatureKind: 'provider_tee',
    });
    const stream = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello SSE' }],
      stream: true,
    });
    let id = '';
    let content = '';
    for await (const event of stream) {
      id = event.id;
      content += event.choices[0]?.delta.content ?? '';
    }
    expect(content).toBe('hello client');
    await expect(client.verifyResponse(id)).resolves.toMatchObject({
      completionId: id,
      signatureKind: 'provider_tee',
    });
    expect(gateway.state.decryptedRequestContent).toEqual([
      'hello JSON',
      'hello SSE',
    ]);
    expect(gateway.state.gatewayAttestationRequests).toBe(1);
    expect(gateway.state.modelAttestationRequests).toBe(1);
    expect(client.pinnedSpkiFingerprints).toEqual([tlsFingerprint]);
    expect(rawFetch).not.toHaveBeenCalled();
    const pinnedPaths = pinnedFetch.mock.calls.map(
      ([request]) => new URL((request as Request).url).pathname,
    );
    expect(pinnedPaths).toEqual([
      '/v1/attestation/report',
      '/ohttp',
      `/v1/signature/${completion.id}`,
      '/ohttp',
      `/v1/signature/${id}`,
    ]);
    for (const request of endpoint.requests) {
      expect(request.headers.get(aggregatorHeader.name)).toBe(
        aggregatorHeader.value,
      );
      if (new URL(request.url).pathname === '/ohttp') {
        expect(request.headers.get('content-type')).toBe(
          'message/ohttp-chunked-req',
        );
        expect(request.headers.has('x-model-pub-key')).toBe(false);
      }
    }
  });

  test.each(['missing', 'model-signed'] as const)(
    'blocks Chat when Gateway OHTTP evidence is %s',
    async (evidence) => {
      const gateway = createTestGateway();
      const endpoint = await createOhttpEndpoint({
        fetch: gateway.fetch,
        signingKey: keyPair(2),
      });
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(
          evidence === 'missing' ? gateway.fetch : endpoint.fetch,
        );
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        ohttp: true,
        signingAlgo: 'ed25519',
      });
      await expect(
        client.fetch(
          `${baseUrl}chat/completions`,
          chatRequest({ messages: [] }),
        ),
      ).rejects.toMatchObject({
        failure: {
          code:
            evidence === 'missing'
              ? 'ohttp.attestation_required'
              : 'ohttp.signer_mismatch',
        },
      });
      expect(gateway.state.completionRequests).toBe(0);
      expect(gateway.state.modelAttestationRequests).toBe(0);
      expect(
        endpoint.requests.every(
          (request) => new URL(request.url).pathname !== '/ohttp',
        ),
      ).toBe(true);
    },
  );

  test('calls browser Fetch with the global receiver', async () => {
    const gateway = createTestGateway();
    const providerFetch = createProviderSignatureFetch(gateway);
    jest.spyOn(globalThis, 'fetch').mockImplementation(function (
      this: typeof globalThis | undefined,
      input,
      init,
    ) {
      // Browser Fetch accepts a standalone call, but not an arbitrary receiver.
      if (this !== undefined && this !== globalThis) {
        throw new TypeError('Illegal invocation');
      }
      return providerFetch(input, init);
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));
    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello' }],
    });
    await expect(client.verifyResponse(completion.id)).resolves.toMatchObject({
      completionId: completion.id,
    });
  });

  test('reuses one OpenAI client for concurrent JSON and streaming responses', async () => {
    const gateway = createTestGateway();
    mockProviderSignatures(gateway);
    const inferenceClient = new InferenceClient(
      inferenceClientOptions(gateway),
    );
    const openai = new OpenAI({
      apiKey: directApiKey,
      baseURL: baseUrl,
      fetch: inferenceClient.fetch,
    });
    const [completion, stream] = await Promise.all([
      openai.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'first' }],
      }),
      openai.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'second' }],
        stream: true,
      }),
    ]);
    let streamId = '';
    let streamVerification: Promise<unknown> | undefined;
    for await (const chunk of stream) {
      streamId = chunk.id;
      // The ID is registered before the first chunk reaches the caller.
      streamVerification ??= inferenceClient.verifyResponse(streamId);
    }
    await expect(streamVerification).resolves.toMatchObject({
      completionId: streamId,
    });
    const verification = inferenceClient.verifyResponse(completion.id);
    expect(inferenceClient.verifyResponse(completion.id)).toBe(verification);
    await expect(verification).resolves.toMatchObject({
      completionId: completion.id,
    });
    expect(inferenceClient.verifyResponse(completion.id)).toBe(verification);
  });

  test.each([
    ['default', undefined, 60 * 60 * 1000],
    ['custom', 1000, 1000],
  ] as const)(
    'expires response records at the %s TTL independently of the attestation cache',
    async (_label, responseCacheTimeToLiveMs, expectedTtl) => {
      const gateway = createTestGateway();
      mockProviderSignatures(gateway);
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        responseCacheTimeToLiveMs,
      });
      jest.useFakeTimers({
        doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'],
      });
      const completion = await client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello' }],
      });
      await client.verifyResponse(completion.id);
      jest.advanceTimersByTime(expectedTtl - 1);
      await expect(client.verifyResponse(completion.id)).resolves.toMatchObject(
        {
          completionId: completion.id,
        },
      );
      jest.advanceTimersByTime(1);
      await expect(client.verifyResponse(completion.id)).rejects.toMatchObject({
        failure: { code: 'api.completion_not_found' },
      });
    },
  );

  test.each([404, 503])(
    'retries response verification after HTTP %i',
    async (status) => {
      const gateway = createTestGateway();
      const providerFetch = createProviderSignatureFetch(gateway);
      let signatureRequests = 0;
      jest.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const request = new Request(input, init);
        if (new URL(request.url).pathname.startsWith('/v1/signature/')) {
          signatureRequests += 1;
          if (signatureRequests === 1) {
            return Promise.resolve(new Response('try again', { status }));
          }
        }
        return providerFetch(request);
      });
      const client = new InferenceClient(inferenceClientOptions(gateway));
      const completion = await client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello' }],
      });

      const firstAttempt = client.verifyResponse(completion.id);
      expect(client.verifyResponse(completion.id)).toBe(firstAttempt);
      await expect(firstAttempt).rejects.toMatchObject({
        failure: { code: 'api.http_status', details: { status } },
        retryable: true,
      });

      const retry = client.verifyResponse(completion.id);
      expect(client.verifyResponse(completion.id)).toBe(retry);
      await expect(retry).resolves.toMatchObject({
        completionId: completion.id,
      });
      expect(client.verifyResponse(completion.id)).toBe(retry);
      expect(signatureRequests).toBe(2);
    },
  );

  test('preserves proxy authorization with an external OpenAI client', async () => {
    const authorization = 'Bearer proxy-token';
    const gateway = createTestGateway({
      expectedRequestHeader: { name: 'authorization', value: authorization },
    });
    mockProviderSignatures(gateway);
    const inferenceClient = new InferenceClient({
      ...inferenceClientOptions(gateway),
      headers: { Authorization: authorization },
    });
    const openai = new OpenAI({
      apiKey: 'unused-placeholder',
      baseURL: baseUrl,
      fetch: inferenceClient.fetch,
      maxRetries: 0,
    });

    const completion = await openai.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello' }],
    });
    await expect(
      inferenceClient.verifyResponse(completion.id),
    ).resolves.toMatchObject({
      completionId: completion.id,
    });
  });

  test.each([true, false])(
    'uses header-only authentication with an external OpenAI client and e2ee=%s',
    async (e2ee) => {
      const gateway = createTestGateway({
        expectedRequestHeader: { name: 'x-api-key', value: 'proxy-key' },
      });
      const providerFetch = createProviderSignatureFetch(gateway);
      const requests: Request[] = [];
      jest.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const request = new Request(input, init);
        requests.push(request);
        return providerFetch(request);
      });
      const inferenceClient = new InferenceClient({
        ...inferenceClientOptions(gateway),
        headers: { 'X-API-Key': 'proxy-key' },
        e2ee,
      });
      const openai = new OpenAI({
        apiKey: 'unused-placeholder',
        baseURL: baseUrl,
        fetch: inferenceClient.fetch,
        maxRetries: 0,
      });

      const completion = await openai.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello' }],
      });
      const verified = await inferenceClient.verifyResponse(completion.id);

      expect(verified.completionId).toBe(completion.id);
      for (const request of requests) {
        expect(request.headers.has('authorization')).toBe(false);
      }
    },
  );

  test('verifies the successful response after an OpenAI retry', async () => {
    const gateway = createTestGateway();
    const providerFetch = createProviderSignatureFetch(gateway);
    let attempts = 0;
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (isChatCompletionRequest(input) && attempts++ === 0) {
        return new Response('retry', {
          status: 503,
          headers: { 'retry-after-ms': '1' },
        });
      }
      return providerFetch(input, init);
    });
    const inferenceClient = new InferenceClient(
      inferenceClientOptions(gateway),
    );
    const openai = new OpenAI({
      apiKey: directApiKey,
      baseURL: baseUrl,
      fetch: inferenceClient.fetch,
    });
    const completion = await openai.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello' }],
    });
    expect(attempts).toBe(2);
    await expect(
      inferenceClient.verifyResponse(completion.id),
    ).resolves.toMatchObject({ completionId: completion.id });
  });

  test('accepts an API key for a direct Gateway connection', async () => {
    const gateway = createTestGateway({
      expectedRequestHeader: {
        name: 'authorization',
        value: `Bearer ${directApiKey}`,
      },
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient({
      apiKey: directApiKey,
      baseUrl,
      gatewayVerification: {
        verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
      },
      modelVerification: { verifiers: { tdxQuote: gateway.tdxQuoteVerifier } },
    });

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 1,
    });
    expect(gateway.state.gatewayAttestationIncludeSpkiFingerprints).toEqual([
      false,
    ]);
  });

  test('reuses verified evidence for the same model for 60 minutes by default', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const now = jest.spyOn(Date, 'now').mockReturnValue(0);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );
    now.mockReturnValue(60 * 60 * 1000 - 1);
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello again' }] }),
    );
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 2,
    });
    now.mockReturnValue(60 * 60 * 1000);
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [{ role: 'user', content: 'refresh evidence' }],
      }),
    );
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 2,
      modelAttestationRequests: 2,
      completionRequests: 3,
    });
  });

  test('verifies every request when the attestation cache time-to-live is zero', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      attestationCacheTimeToLiveMs: 0,
    });

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello again' }] }),
    );

    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 2,
      modelAttestationRequests: 2,
      completionRequests: 2,
    });
  });

  test('refreshes verified evidence after its cache time-to-live expires', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const now = jest.spyOn(Date, 'now').mockReturnValue(0);
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      attestationCacheTimeToLiveMs: 100,
    });

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );
    now.mockReturnValue(100);
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello again' }] }),
    );

    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 2,
      modelAttestationRequests: 2,
      completionRequests: 2,
    });
  });

  test('verifies the requested model and passes it to the deployment policy', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const policyModels: string[] = [];
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      deploymentPolicy: ({ model: policyModel }) => {
        policyModels.push(policyModel);
      },
    });

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'first model' }] }),
    );
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        model: secondModel,
        messages: [{ role: 'user', content: 'second model' }],
      }),
    );

    expect(gateway.state.modelAttestationModels).toEqual([model, secondModel]);
    expect(policyModels).toEqual([model, secondModel]);
  });

  test('supports a model deployment verifier without a deployment policy', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const deployment = jest.fn();
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      modelVerification: {
        verifiers: { tdxQuote: gateway.tdxQuoteVerifier, deployment },
      },
    });

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    expect(deployment).toHaveBeenCalledTimes(1);
    expect(deployment).toHaveBeenCalledWith({
      provider: 'near',
      appCompose,
      runtimeMeasurements: expect.any(Object),
    });
    expect(gateway.state.completionRequests).toBe(1);
  });

  test('awaits the model deployment verifier before the policy and Chat', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const calls: string[] = [];
    const deployment = jest.fn(async () => {
      calls.push('verifier started');
      await Promise.resolve();
      calls.push('verifier finished');
    });
    const deploymentPolicy = jest.fn(async () => {
      expect(calls).toEqual(['verifier started', 'verifier finished']);
      calls.push('policy started');
      await Promise.resolve();
      calls.push('policy finished');
      expect(gateway.state.completionRequests).toBe(0);
    });
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      modelVerification: {
        verifiers: { tdxQuote: gateway.tdxQuoteVerifier, deployment },
      },
      deploymentPolicy,
    });

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );
    expect(deploymentPolicy).toHaveBeenCalledWith({
      model,
      deployment: {
        provider: 'near',
        appCompose,
        runtimeMeasurements: expect.any(Object),
      },
    });
    expect(calls).toEqual([
      'verifier started',
      'verifier finished',
      'policy started',
      'policy finished',
    ]);
    expect(gateway.state.completionRequests).toBe(1);
  });

  test('caches verified sessions by exact model', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'first model' }] }),
    );
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        model: secondModel,
        messages: [{ role: 'user', content: 'second model' }],
      }),
    );
    await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({
        messages: [{ role: 'user', content: 'first model again' }],
      }),
    );

    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 2,
      modelAttestationRequests: 2,
      completionRequests: 3,
    });
    expect(gateway.state.modelAttestationModels).toEqual([model, secondModel]);
  });

  test('keeps concurrent verification separate for different models', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await Promise.all([
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'first model' }] }),
      ),
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({
          model: secondModel,
          messages: [{ role: 'user', content: 'second model' }],
        }),
      ),
    ]);

    expect(gateway.state.modelAttestationModels).toEqual(
      expect.arrayContaining([model, secondModel]),
    );
    expect(gateway.state.modelAttestationRequests).toBe(2);
  });

  test('shares concurrent verification for the same model', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await Promise.all([
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'first request' }] }),
      ),
      client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({
          messages: [{ role: 'user', content: 'second request' }],
        }),
      ),
    ]);

    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 2,
    });
  });

  test('aborts one caller without cancelling shared attestation verification', async () => {
    const gateway = createTestGateway();
    let gatewayAttestationRequest: Request | undefined;
    let resolveGatewayAttestation: (response: Response) => void = () => {};
    const gatewayAttestationResponse = new Promise<Response>((resolve) => {
      resolveGatewayAttestation = resolve;
    });
    let notifyGatewayAttestationStarted: () => void = () => {};
    const gatewayAttestationStarted = new Promise<void>((resolve) => {
      notifyGatewayAttestationStarted = resolve;
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (
        url.pathname === '/v1/attestation/report' &&
        !url.searchParams.has('model')
      ) {
        gatewayAttestationRequest = request;
        notifyGatewayAttestationStarted();
        return gatewayAttestationResponse;
      }
      return gateway.fetch(request);
    });
    const client = new InferenceClient(inferenceClientOptions(gateway));
    const controller = new AbortController();

    const aborted = client.fetch(`${baseUrl}chat/completions`, {
      ...chatRequest({ messages: [{ role: 'user', content: 'cancel me' }] }),
      signal: controller.signal,
    });
    await gatewayAttestationStarted;

    const succeeding = client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'still send me' }] }),
    );
    controller.abort();

    await expect(aborted).rejects.toMatchObject({ name: 'AbortError' });
    if (gatewayAttestationRequest === undefined) {
      throw new Error('Expected a Gateway attestation request');
    }
    resolveGatewayAttestation(await gateway.fetch(gatewayAttestationRequest));

    await expect(succeeding).resolves.toBeInstanceOf(Response);
    expect(gateway.state).toMatchObject({
      gatewayAttestationRequests: 1,
      modelAttestationRequests: 1,
      completionRequests: 1,
    });
  });

  test('requires a model before it fetches attestation evidence', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    await expect(
      client.fetch(`${baseUrl}chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          messages: [{ role: 'user', content: 'hello model' }],
        }),
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'api.invalid_input',
        details: { field: 'request body' },
      },
    });
    expect(gateway.state.gatewayAttestationRequests).toBe(0);
    expect(gateway.state.modelAttestationRequests).toBe(0);
  });

  test('blocks an E2EE request when model evidence has no signing public key', async () => {
    const gateway = createTestGateway({ includeModelPublicKey: false });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));
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
    mockProviderSignatures(gateway);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
    );

    await expect(response.json()).resolves.toMatchObject({
      choices: [{ message: { content: 'hello client' } }],
    });
    expect(gateway.state.decryptedRequestContent).toEqual(['hello model']);
    await expect(client.verifyResponse('chatcmpl-test')).resolves.toMatchObject(
      {
        signatureKind: 'provider_tee',
        attestation: {
          signer: { signingAddress: keyHex(keyPair(2).publicKey) },
        },
      },
    );
  });

  test('rejects a provider signature from a different verified model candidate', async () => {
    const gateway = createTestGateway({ includeSecondModelAttestation: true });
    const signWithSelectedKey = gateway.createProviderSignature;
    const otherKey = keyPair(3);
    jest
      .spyOn(gateway, 'createProviderSignature')
      .mockImplementation((requestBody, responseBody) => {
        const signature = signWithSelectedKey(requestBody, responseBody);
        return {
          ...signature,
          signing_address: keyHex(otherKey.publicKey),
          signature: keyHex(
            nacl.sign.detached(Buffer.from(signature.text), otherKey.secretKey),
          ),
        };
      });
    mockProviderSignatures(gateway);
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      e2ee: false,
    });
    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello' }],
    });

    expect(
      gateway.state.completionRequestsSeen[0].headers.get('x-model-pub-key'),
    ).toBe(keyHex(keyPair(2).publicKey));
    const verification = client.verifyResponse(completion.id);
    await expect(verification).rejects.toMatchObject({
      failure: { code: 'signature.signer_mismatch' },
    });
    expect(client.verifyResponse(completion.id)).toBe(verification);
  });

  test('decrypts a Chat Completions stream split across transport chunks', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

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

  test.each(['\n\n', '\r\n\r\n'])(
    'registers the first SSE event ending in %j before the next event arrives',
    async (separator) => {
      const gateway = createTestGateway({
        streamRecordSeparators: [separator],
      });
      const providerFetch = createProviderSignatureFetch(gateway);
      let resumeStream: () => void = () => {};
      const nextEventReady = new Promise<void>((resolve) => {
        resumeStream = resolve;
      });
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(async (input, init) => {
          const response = await providerFetch(input, init);
          if (!isChatCompletionRequest(input)) return response;
          let chunks = 0;
          return new Response(
            response.body?.pipeThrough(
              new TransformStream<Uint8Array, Uint8Array>({
                async transform(chunk, controller) {
                  // The fixture splits its first event into two transport chunks.
                  if (chunks === 2) await nextEventReady;
                  chunks += 1;
                  controller.enqueue(chunk);
                },
              }),
            ),
            { headers: response.headers },
          );
        });
      const client = new InferenceClient(inferenceClientOptions(gateway));
      const stream = await client.chat.completions.create({
        model,
        messages: [{ role: 'user', content: 'hello model' }],
        stream: true,
      });
      const iterator = stream[Symbol.asyncIterator]();
      const first = await iterator.next();
      expect(first.value?.choices[0]?.delta.content).toBe('hello ');
      const verification = expect(
        client.verifyResponse('chatcmpl-stream'),
      ).resolves.toMatchObject({
        completionId: 'chatcmpl-stream',
        signatureKind: 'provider_tee',
      });

      resumeStream();
      expect((await iterator.next()).value?.choices[0]?.delta.content).toBe(
        'client',
      );
      expect((await iterator.next()).done).toBe(true);
      await verification;
    },
  );

  test('returns a non-streaming completion with verifiable entity bodies', async () => {
    const gateway = createTestGateway();
    mockProviderSignatures(gateway);
    const client = new InferenceClient(inferenceClientOptions(gateway));

    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello model' }],
    });

    expect(completion.choices[0]?.message.content).toBe('hello client');
    await expect(client.verifyResponse(completion.id)).resolves.toMatchObject({
      completionId: 'chatcmpl-test',
      signatureKind: 'provider_tee',
    });
  });

  test.each([
    {
      name: 'CRLF',
      separators: ['\r\n\r\n', '\r\n\r\n', '\r\n\r\n', '\r\n\r\n'],
    },
    { name: 'mixed', separators: ['\n\r\n', '\r\n\n', '\n\r', '\r\n\r'] },
  ])(
    'verifies multiline SSE with $name record separators after consuming the stream',
    async ({ separators }) => {
      const gateway = createTestGateway({
        streamRecordSeparators: separators,
      });
      mockProviderSignatures(gateway);
      const client = new InferenceClient(inferenceClientOptions(gateway));

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
      await expect(
        client.verifyResponse('chatcmpl-stream'),
      ).resolves.toMatchObject({
        completionId: 'chatcmpl-stream',
        signatureKind: 'provider_tee',
      });
    },
  );

  test('supports a non-streaming OpenAI-compatible chat call', async () => {
    const gateway = createTestGateway({
      expectedRequestHeader: {
        name: 'authorization',
        value: 'Bearer browser-token',
      },
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient({
      baseUrl,
      headers: { authorization: 'Bearer browser-token' },
      gatewayVerification: {
        verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
      },
      modelVerification: { verifiers: { tdxQuote: gateway.tdxQuoteVerifier } },
    });

    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello model' }],
    });

    expect(completion.choices[0]?.message.content).toBe('plaintext response');
    expect(gateway.state.completionRequestsSeen[0].body.messages).toEqual([
      { role: 'user', content: 'hello model' },
    ]);
    expect(
      gateway.state.completionRequestsSeen[0].headers.has('x-client-pub-key'),
    ).toBe(false);
  });

  test('accepts nullable and empty Chat response fields under E2EE', async () => {
    const gateway = createTestGateway({ includeNullableResponseFields: true });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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
    mockProviderSignatures(gateway);
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      e2ee: false,
    });
    const richContent = [{ type: 'text', text: 'plain Chat payload' }];

    const response = await client.fetch(
      `${baseUrl}chat/completions`,
      chatRequest({ messages: [{ role: 'user', content: richContent }] }),
    );

    const completion = await response.json();
    expect(completion).toMatchObject({
      choices: [{ message: { content: 'plaintext response' } }],
    });
    await expect(client.verifyResponse(completion.id)).resolves.toMatchObject({
      signatureKind: 'provider_tee',
      signature: { signer: { signingAlgo: 'ed25519' } },
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
    expect(request.headers.get('x-signing-algo')).toBeNull();
    expect(request.headers.get('x-client-pub-key')).toBeNull();
    expect(request.headers.get('x-model-pub-key')).toBe(
      keyHex(keyPair(2).publicKey),
    );
  });

  test.each(['verifier', 'policy'])(
    'does not send a completion when the model deployment %s rejects it',
    async (rejectedHook) => {
      const gateway = createTestGateway();
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      const deployment = jest.fn(async () => {
        if (rejectedHook === 'verifier')
          throw new Error('deployment is not approved');
      });
      const deploymentPolicy = jest.fn(async () => {
        if (rejectedHook === 'policy')
          throw new Error('deployment is not approved');
      });
      const client = new InferenceClient({
        ...inferenceClientOptions(gateway),
        modelVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier, deployment },
        },
        deploymentPolicy,
      });

      await expect(
        client.fetch(
          `${baseUrl}chat/completions`,
          chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
        ),
      ).rejects.toMatchObject({
        failure: { code: 'provenance.verification_failed' },
      });
      expect(deployment).toHaveBeenCalledTimes(1);
      expect(deploymentPolicy).toHaveBeenCalledTimes(
        rejectedHook === 'verifier' ? 0 : 1,
      );
      expect(gateway.state.completionRequests).toBe(0);
    },
  );

  test('does not send a completion when model verification fails', async () => {
    const gateway = createTestGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient({
      ...inferenceClientOptions(gateway),
      modelVerification: {
        verifiers: {
          tdxQuote: () => {
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
    const client = new InferenceClient(inferenceClientOptions(gateway));
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
    const client = new InferenceClient(inferenceClientOptions(gateway));

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

  describe('Node inference client', () => {
    test('binds Gateway evidence to the TLS peer by default', async () => {
      const gateway = createTestGateway();
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      const capturedPeerSpkiFingerprints = mockNodeGatewayAttestation({
        gateway,
      });
      const client = new TestNodeInferenceClient(
        inferenceClientOptions(gateway),
        gateway.fetch,
      );

      await client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      );

      expect(capturedPeerSpkiFingerprints).toEqual([true]);
      expect(client.pinnedSpkiFingerprints).toEqual([tlsFingerprint]);
      expect(gateway.state.gatewayAttestationIncludeSpkiFingerprints).toEqual([
        true,
      ]);
      expect(gateway.state.completionRequests).toBe(1);
    });

    test('uses the pinned transport for model evidence, completion, and its response signature', async () => {
      const gateway = createTestGateway();
      const providerFetch = createProviderSignatureFetch(gateway);
      const pinnedPaths: string[] = [];
      const pinnedFetch: typeof globalThis.fetch = async (input, init) => {
        const url =
          input instanceof Request ? input.url : new URL(input).toString();
        pinnedPaths.push(new URL(url).pathname);
        return providerFetch(input, init);
      };
      jest.spyOn(globalThis, 'fetch').mockImplementation(async () => {
        throw new Error('Unexpected unpinned Gateway request');
      });
      mockNodeGatewayAttestation({ gateway });
      const client = new TestNodeInferenceClient(
        inferenceClientOptions(gateway),
        pinnedFetch,
      );

      const response = await client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      );
      await response.text();
      await client.verifyResponse('chatcmpl-test');

      expect(client.pinnedSpkiFingerprints).toEqual([tlsFingerprint]);
      expect(pinnedPaths).toEqual([
        '/v1/attestation/report',
        '/v1/chat/completions',
        '/v1/signature/chatcmpl-test',
      ]);
    });

    test('can disable Gateway TLS binding for an aggregator or proxy', async () => {
      const gateway = createTestGateway();
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      const capturedPeerSpkiFingerprints = mockNodeGatewayAttestation({
        gateway,
      });
      const client = new NodeInferenceClient({
        ...inferenceClientOptions(gateway),
        gatewayVerification: {
          includeSpkiFingerprint: false,
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
      });

      await client.fetch(
        `${baseUrl}chat/completions`,
        chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
      );

      expect(capturedPeerSpkiFingerprints).toEqual([false]);
      expect(gateway.state.gatewayAttestationIncludeSpkiFingerprints).toEqual([
        false,
      ]);
      expect(gateway.state.completionRequests).toBe(1);
    });

    test('blocks the completion when the Gateway TLS peer does not match', async () => {
      const gateway = createTestGateway();
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      mockNodeGatewayAttestation({
        gateway,
        peerSpkiFingerprint: '44'.repeat(32),
      });
      const client = new NodeInferenceClient(inferenceClientOptions(gateway));

      await expect(
        client.fetch(
          `${baseUrl}chat/completions`,
          chatRequest({ messages: [{ role: 'user', content: 'hello model' }] }),
        ),
      ).rejects.toMatchObject({
        failure: { code: 'binding.spki_fingerprint_mismatch' },
      });
      expect(gateway.state.modelAttestationRequests).toBe(0);
      expect(gateway.state.completionRequests).toBe(0);
    });
  });
});
