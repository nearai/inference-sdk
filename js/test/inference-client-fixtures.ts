import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import ed2curve from 'ed2curve';
import nacl from 'tweetnacl';
import type {
  InferenceClient,
  InferenceClientOptions,
  TdxQuoteVerificationResult,
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

export const baseUrl = 'https://gateway.test/v1/';

export const model = 'glm-5.3-flash';

export const aggregatorHeader = {
  name: 'x-aggregator-token',
  value: 'aggregator-token',
};

export const eventLog = [
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
  readonly metadataModels: string[];
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

export type TestGateway = {
  readonly fetch: typeof globalThis.fetch;
  readonly expectRequestHeader: (request: Request) => void;
  readonly createProviderSignature: (
    requestBody: Uint8Array,
    responseBody: Uint8Array,
  ) => Record<string, string>;
  readonly createGatewaySignature: (
    requestBody: Uint8Array,
    responseBody: Uint8Array,
  ) => Record<string, string>;
  readonly tdxQuoteVerifier: (quote: string) => TdxQuoteVerificationResult;
  readonly state: TestGatewayState;
};

type CreateTestGatewayParams = {
  readonly expectedRequestHeader?: {
    readonly name: string;
    readonly value: string | null;
  };
  readonly includeModelPublicKey?: boolean;
  readonly providerType?: string;
  readonly attestationSupported?: boolean;
  readonly includeNullableResponseFields?: boolean;
  readonly includeSecondModelAttestation?: boolean;
  readonly sharedModelSigner?: boolean;
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

export function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: { 'content-type': 'application/json' },
  });
}

export function keyPair(seed: number): nacl.SignKeyPair {
  return nacl.sign.keyPair.fromSeed(Buffer.alloc(32, seed));
}

export function keyHex(key: Uint8Array): string {
  return Buffer.from(key).toString('hex');
}

type EncryptEd25519TextParams = {
  readonly plaintext: string;
  readonly recipientPublicKey: string;
};

export function encryptE2eeText({
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

export function fixtureId(id: string, requestNumber: number): string {
  return requestNumber === 1 ? id : `${id}-${requestNumber}`;
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
    headers: {
      'content-type': 'text/event-stream',
      'x-test-completion-id':
        events.join('').match(/"id":"([^"]+)"/)?.[1] ?? '',
    },
  });
}

export function createTestGateway({
  expectedRequestHeader = aggregatorHeader,
  includeModelPublicKey = true,
  providerType = 'vllm',
  attestationSupported = true,
  includeNullableResponseFields = false,
  includeSecondModelAttestation = false,
  sharedModelSigner = false,
  encryptedRefusal,
  streamRecordSeparators,
}: CreateTestGatewayParams = {}): TestGateway {
  const gatewayKeyPair = keyPair(1);
  const modelKeyPair = keyPair(2);
  const secondModelKeyPair = sharedModelSigner ? modelKeyPair : keyPair(3);
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
    metadataModels: [],
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
    quoteSuffix = '',
  ) {
    const quoteId = `${keyHex(signingKeyPair.publicKey)}:${nonce}${quoteSuffix}`;
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
    const url = new URL(request.url);
    if (
      url.pathname === '/v1/attestation/report' &&
      !url.searchParams.has('model')
    ) {
      for (const name of ['authorization', 'api-key', 'x-api-key']) {
        expect(request.headers.has(name)).toBe(false);
      }
      if (
        ['authorization', 'api-key', 'x-api-key'].includes(
          expectedRequestHeader.name,
        )
      ) {
        return;
      }
    }
    expect(request.headers.get(expectedRequestHeader.name)).toBe(
      expectedRequestHeader.value,
    );
  }

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    expectRequestHeader(request);

    if (url.pathname.startsWith('/v1/model/')) {
      expect(request.method).toBe('GET');
      state.metadataModels.push(
        decodeURIComponent(url.pathname.slice('/v1/model/'.length)),
      );
      return jsonResponse({
        metadata: { providerType, attestationSupported },
      });
    }

    if (url.pathname === '/v1/attestation/report') {
      const nonce = url.searchParams.get('nonce');
      if (nonce === null) {
        throw new Error('Expected an attestation nonce');
      }
      if (url.searchParams.has('model')) {
        expect(url.searchParams.get('provider')).toBe('near');
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
                    undefined,
                    sharedModelSigner ? ':replica-2' : '',
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
    const requestNumber = state.completionRequests;
    const body = JSON.parse(await request.text()) as Record<string, unknown>;
    state.completionRequestsSeen.push({ body, headers: request.headers });

    const clientPublicKey = request.headers.get('x-client-pub-key');
    if (clientPublicKey === null) {
      if (body.stream === true) {
        return streamResponse([
          `data: ${JSON.stringify({
            id: fixtureId('chatcmpl-stream', requestNumber),
            object: 'chat.completion.chunk',
            created: 0,
            model,
            choices: [
              {
                index: 0,
                delta: { content: 'plaintext response' },
                finish_reason: 'stop',
              },
            ],
          })}\n\n`,
          'data: [DONE]\n\n',
          ': response complete\n\n',
        ]);
      }
      return jsonResponse({
        id: fixtureId('chatcmpl-plaintext', requestNumber),
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
          id: fixtureId('chatcmpl-web-context-search', requestNumber),
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
          id: fixtureId('chatcmpl-web-context-search', requestNumber),
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
          id: fixtureId('chatcmpl-tool-stream', requestNumber),
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
        id: fixtureId('chatcmpl-stream', requestNumber),
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
        id: fixtureId('chatcmpl-stream', requestNumber),
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
      id: fixtureId('chatcmpl-test', requestNumber),
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
    createGatewaySignature(requestBody, responseBody) {
      const text = `${hashBytes(requestBody)}:${hashBytes(responseBody)}`;
      return {
        text,
        signature: keyHex(
          nacl.sign.detached(Buffer.from(text), gatewayKeyPair.secretKey),
        ),
        signing_address: keyHex(gatewayKeyPair.publicKey),
        signing_algo: 'ed25519',
        signature_kind: 'gateway',
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

export function inferenceClientOptions(
  gateway: TestGateway,
): InferenceClientOptions {
  return {
    baseUrl,
    e2ee: true,
    headers: { [aggregatorHeader.name]: aggregatorHeader.value },
    gatewayVerification: { verifiers: { tdxQuote: gateway.tdxQuoteVerifier } },
    modelVerification: { verifiers: { tdxQuote: gateway.tdxQuoteVerifier } },
  };
}

export type NodeAttestationClientPrototype = {
  requestGatewayAttestation: (
    request: Request,
    capturePeerSpkiFingerprint: boolean,
  ) => Promise<GatewayAttestationHttpResponse>;
};

type MockNodeGatewayAttestationParams = {
  readonly gateway: TestGateway;
  readonly peerSpkiFingerprint?: string;
};

export class TestNodeInferenceClient extends NodeInferenceClient {
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

export function mockNodeGatewayAttestation({
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

export function chatRequest(body: Record<string, unknown>): RequestInit {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model, ...body }),
  };
}

export function createSignatureFetch(
  gateway: TestGateway,
  kind: 'provider_tee' | 'gateway' = 'provider_tee',
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
        ? (response.headers.get('x-test-completion-id') ?? '')
        : (await response.clone().json()).id;
    signatures.set(
      completionId,
      response
        .clone()
        .arrayBuffer()
        .then((responseBody) =>
          gateway[
            kind === 'gateway'
              ? 'createGatewaySignature'
              : 'createProviderSignature'
          ](requestBody, new Uint8Array(responseBody)),
        ),
    );
    return response;
  };
}

export function retainedCapture(client: InferenceClient, id: string): unknown {
  const records = Reflect.get(client, 'responseRecords') as Map<
    string,
    { captured?: unknown }
  >;
  return records.get(id)?.captured;
}
