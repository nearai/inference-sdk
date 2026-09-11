import OpenAI from 'openai';
import type { Stream } from 'openai/streaming';
import * as v from 'valibot';
import {
  ChatCompletionRequestSchema,
  CompletionResponseIdSchema,
} from '../schemas';
import type {
  ModelAttestationVerifiers,
  VerifiedGatewayAttestation,
  VerifiedModelAttestation,
} from '../types/verification';
import type {
  CompletionReceipt,
  NearAiSecureClientOptions,
  SecureChat,
  SecureChatCompletionRequest,
  SecureChatCompletionResponse,
  SecureChatCompletionStreamWithReceipt,
  SecureChatCompletionWithReceipt,
  SecureChatCompletions,
  SecureClientOptions,
  SecureFetchWithReceipt,
  VerifiedCompletionReceipt,
} from '../types/secure-client';
import { ApiError, VerificationError } from '../utils/errors';
import {
  AttestationClient,
  findModelAttestationForSignature,
  getAuthorizationToken,
  NO_ALIASING_HEADER,
  resolveCloudApiBaseUrl,
} from './cloud-api';
import { verifyGatewayAttestation } from './attestation-gateway';
import { verifyModelAttestation } from './attestation-model';
import { verifyGatewayResponse, verifyModelResponse } from './chat';
import {
  createE2eeChatSseTransform,
  decryptE2eeChatResponse,
  encryptE2eeChatRequest,
  parseE2eeChatResponse,
} from './e2ee-chat';
import { createE2eeClientKeyPair, type E2eeClientKeyPair } from './e2ee';

type SecureSessionState = {
  readonly gatewayAttestation: VerifiedGatewayAttestation;
  readonly modelAttestations: readonly VerifiedModelAttestation[];
  readonly modelSigningPublicKey: string;
};

type ParsedPlaintextRequest = {
  readonly e2ee: false;
  readonly model: string;
  readonly request: Request;
};

type ParsedE2eeRequest = {
  readonly e2ee: true;
  readonly model: string;
  readonly request: Request;
  readonly body: SecureChatCompletionRequest;
};

type ParsedSecureRequest = ParsedPlaintextRequest | ParsedE2eeRequest;

type EncryptSecureRequestParams = {
  readonly parsed: ParsedE2eeRequest;
  readonly modelSigningPublicKey: string;
};

type EncryptedSecureRequest = {
  readonly request: Request;
  readonly clientKeyPair: E2eeClientKeyPair;
};

type DecryptSecureResponseParams = {
  readonly response: Response;
  readonly clientKeyPair: E2eeClientKeyPair;
};

type DecodeChatRequestParams = {
  readonly request: Request;
};

type PreparePlaintextRequestParams = {
  readonly request: Request;
  readonly modelSigningPublicKey: string;
};

type SendSecureCompletionParams = {
  readonly input: RequestInfo | URL;
  readonly init?: RequestInit;
  readonly captureReceipt: boolean;
};

type SendSecureCompletionWithReceiptParams = Omit<
  SendSecureCompletionParams,
  'captureReceipt'
> & {
  readonly captureReceipt: true;
};

type SendSecureCompletionWithoutReceiptParams = Omit<
  SendSecureCompletionParams,
  'captureReceipt'
> & {
  readonly captureReceipt: false;
};

type SentSecureCompletion = {
  readonly response: Response;
  readonly session: SecureSessionState;
  readonly clientKeyPair?: E2eeClientKeyPair;
};

type CapturedSecureCompletion = SentSecureCompletion & {
  readonly requestBody: Promise<Uint8Array>;
  readonly responseBody: Promise<Uint8Array>;
};

type CapturedResponseEntityBody = {
  readonly response: Response;
  readonly responseBody: Promise<Uint8Array>;
};

type VerifyCapturedCompletionParams = {
  readonly requestBody: Uint8Array;
  readonly responseBody: Promise<Uint8Array>;
  readonly session: SecureSessionState;
  readonly contentType: string | null;
};

type ClearPendingVerificationParams = {
  readonly model: string;
  readonly verification: Promise<SecureSessionState>;
};

type CreateOpenAiClientParams = {
  readonly authorizationToken: string;
  readonly baseUrl: string;
  readonly fetch: typeof globalThis.fetch;
};

type OpenAiChatCompletionCreateParamsBase = Parameters<
  OpenAI.Chat.Completions['create']
>[0];

/**
 * A verified Chat Completions transport.
 *
 * Every `fetch()` call reads its model from the Chat request, then obtains and
 * verifies fresh Gateway and model evidence before dispatch. With the default
 * `e2ee: true`, supported fields are then encrypted to a quote-bound model key
 * and integrity-checked on the way back.
 * With `e2ee: false`, the same evidence and policy checks run, but the Chat
 * request and response remain plaintext while the request stays pinned to the
 * verified model key.
 */
export class SecureClient {
  private readonly attestationClient: AttestationClient;
  private readonly authorizationToken: string;
  private readonly baseUrl: string;
  private readonly e2eeEnabled: boolean;
  private readonly options: SecureClientOptions;
  /** Shares only same-model work already in progress; completed evidence is never cached. */
  private readonly pendingVerifications = new Map<
    string,
    Promise<SecureSessionState>
  >();

  constructor(options: SecureClientOptions) {
    this.attestationClient = new AttestationClient(options);
    this.authorizationToken = getAuthorizationToken(options);
    this.baseUrl = resolveCloudApiBaseUrl(options.baseUrl);
    this.e2eeEnabled = options.e2ee !== false;
    this.options = options;
  }

  /** Base URL to pair with this client's verified `fetch` implementation. */
  getBaseUrl(): string {
    return this.baseUrl;
  }

  /**
   * Send one verified Chat Completions request.
   *
   * Only POST requests to this client's configured Chat Completions endpoint
   * are accepted. Other API paths, including Responses, are rejected locally.
   */
  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const completion = await this.sendSecureCompletion({
      input,
      init,
      captureReceipt: false,
    });
    return this.toClientResponse(completion);
  }

  /**
   * Send one verified Chat Completions request and retain its exact entity-body
   * bytes for later completion-signature verification.
   */
  async fetchWithReceipt(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<SecureFetchWithReceipt> {
    const completion = await this.sendSecureCompletion({
      input,
      init,
      captureReceipt: true,
    });
    const requestBody = await completion.requestBody;
    const responseBody = completion.responseBody;

    return {
      response: await this.toClientResponse(completion),
      receipt: this.createCompletionReceipt({
        requestBody,
        responseBody,
        session: completion.session,
        contentType: completion.response.headers.get('content-type'),
      }),
    };
  }

  private sendSecureCompletion(
    params: SendSecureCompletionWithReceiptParams,
  ): Promise<CapturedSecureCompletion>;
  private sendSecureCompletion(
    params: SendSecureCompletionWithoutReceiptParams,
  ): Promise<SentSecureCompletion>;
  private async sendSecureCompletion({
    input,
    init,
    captureReceipt,
  }: SendSecureCompletionParams): Promise<
    SentSecureCompletion | CapturedSecureCompletion
  > {
    const parsed = await this.parseSecureRequest(input, init);
    const session = await this.startVerification(parsed.model);

    const prepared = parsed.e2ee
      ? this.encryptSecureRequest({
          parsed,
          modelSigningPublicKey: session.modelSigningPublicKey,
        })
      : {
          request: this.preparePlaintextRequest({
            request: parsed.request,
            modelSigningPublicKey: session.modelSigningPublicKey,
          }),
        };
    const clientKeyPair =
      'clientKeyPair' in prepared ? prepared.clientKeyPair : undefined;
    if (!captureReceipt) {
      return {
        response: await this.sendCompletionRequest(prepared.request),
        session,
        ...(clientKeyPair === undefined ? {} : { clientKeyPair }),
      };
    }

    const requestBody = captureRequestEntityBody(prepared.request);
    const response = await this.sendCompletionRequest(prepared.request);
    const capturedResponse = captureResponseEntityBody(response);
    return {
      response: capturedResponse.response,
      session,
      requestBody,
      responseBody: capturedResponse.responseBody,
      ...(clientKeyPair === undefined ? {} : { clientKeyPair }),
    };
  }

  private async toClientResponse({
    response,
    clientKeyPair,
  }: SentSecureCompletion): Promise<Response> {
    if (clientKeyPair === undefined || !response.ok) {
      return response;
    }
    return this.decryptSecureResponse({
      response,
      clientKeyPair,
    });
  }

  private createCompletionReceipt({
    requestBody,
    responseBody,
    session,
    contentType,
  }: VerifyCapturedCompletionParams): CompletionReceipt {
    return {
      requestBody,
      responseBody,
      verify: () =>
        this.verifyCapturedCompletion({
          requestBody,
          responseBody,
          session,
          contentType,
        }),
    };
  }

  private async verifyCapturedCompletion({
    requestBody,
    responseBody,
    session,
    contentType,
  }: VerifyCapturedCompletionParams): Promise<VerifiedCompletionReceipt> {
    const bytes = await responseBody;
    const completionId = getCompletionId({ bytes, contentType });
    const signature = await this.attestationClient.fetchCompletionSignature({
      completionId,
      signingAlgo: 'ed25519',
    });

    if (signature.kind === 'provider_tee') {
      const attestation = findModelAttestationForSignature({
        attestations: session.modelAttestations,
        signature,
      });
      verifyModelResponse({
        requestBody,
        responseBody: bytes,
        signature,
        attestation,
      });
      return {
        completionId,
        signatureKind: 'provider_tee',
        signature,
        attestation,
      };
    }

    verifyGatewayResponse({
      requestBody,
      responseBody: bytes,
      signature,
      attestation: session.gatewayAttestation,
    });
    return {
      completionId,
      signatureKind: 'gateway',
      signature,
      attestation: session.gatewayAttestation,
    };
  }

  private startVerification(model: string): Promise<SecureSessionState> {
    const existing = this.pendingVerifications.get(model);
    if (existing !== undefined) {
      return existing;
    }

    const verification = this.createVerificationState(model);
    this.pendingVerifications.set(model, verification);
    void verification.then(
      () => this.clearPendingVerification({ model, verification }),
      () => this.clearPendingVerification({ model, verification }),
    );
    return verification;
  }

  private clearPendingVerification({
    model,
    verification,
  }: ClearPendingVerificationParams): void {
    if (this.pendingVerifications.get(model) === verification) {
      this.pendingVerifications.delete(model);
    }
  }

  private async createVerificationState(
    model: string,
  ): Promise<SecureSessionState> {
    const [gateway, fetchedModels] = await Promise.all([
      this.attestationClient.fetchGatewayAttestation({
        signingAlgo: 'ed25519',
        includeSpkiFingerprint: false,
      }),
      this.attestationClient.fetchModelAttestations({
        model,
        signingAlgo: 'ed25519',
      }),
    ]);
    if (fetchedModels.attestations.length === 0) {
      throw new VerificationError({
        code: 'policy.model_attestation_required',
      });
    }

    const modelVerifiers = this.getModelVerifiers(model);
    const [gatewayAttestation, modelAttestations] = await Promise.all([
      verifyGatewayAttestation({
        attestation: gateway.attestation,
        clientBinding: gateway.clientBinding,
        policy: this.options.gatewayVerification?.policy,
        verifiers: this.options.gatewayVerification?.verifiers,
      }),
      Promise.all(
        fetchedModels.attestations.map((attestation) =>
          verifyModelAttestation({
            attestation,
            clientBinding: fetchedModels.clientBinding,
            policy: this.options.modelVerification?.policy,
            verifiers: modelVerifiers,
          }),
        ),
      ),
    ]);
    const modelSigningPublicKey =
      selectModelSigningPublicKey(modelAttestations);

    return {
      gatewayAttestation,
      modelAttestations,
      modelSigningPublicKey,
    };
  }

  private getModelVerifiers(
    model: string,
  ): ModelAttestationVerifiers | undefined {
    const verifiers = this.options.modelVerification?.verifiers;
    const deploymentPolicy = this.options.deploymentPolicy;
    if (verifiers?.deployment === undefined && deploymentPolicy === undefined) {
      return verifiers;
    }
    return {
      ...verifiers,
      deployment: async (deployment) => {
        await verifiers?.deployment?.(deployment);
        await deploymentPolicy?.({ model, deployment });
      },
    };
  }

  private async parseSecureRequest(
    input: RequestInfo | URL,
    init: RequestInit | undefined,
  ): Promise<ParsedSecureRequest> {
    const request = createRequest(input, init);
    this.requireSupportedEndpoint(request);
    const value = await decodeChatRequest({ request });
    const generic = v.safeParse(ChatCompletionRequestSchema, value);
    if (!generic.success) {
      throw invalidInput({
        field: 'request body',
        reason: 'unsupported_value',
        expected: 'a JSON Chat Completions request with a string model',
      });
    }
    const model = generic.output.model;
    if (this.e2eeEnabled) {
      const body = generic.output as SecureChatCompletionRequest;
      return {
        e2ee: true,
        model,
        request,
        body,
      };
    }
    return { e2ee: false, model, request };
  }

  private requireSupportedEndpoint(request: Request): void {
    const url = new URL(request.url);
    const baseUrl = new URL(this.baseUrl);
    const chatPath = new URL('chat/completions', this.baseUrl).pathname;
    if (
      request.method !== 'POST' ||
      url.origin !== baseUrl.origin ||
      url.pathname !== chatPath
    ) {
      throw invalidInput({
        field: 'request',
        reason: 'unsupported_value',
        expected: 'a POST to the configured Chat Completions endpoint',
        actual: `${request.method} ${url.pathname}`,
      });
    }
  }

  private preparePlaintextRequest({
    request,
    modelSigningPublicKey,
  }: PreparePlaintextRequestParams): Request {
    const headers = new Headers(request.headers);
    headers.set('authorization', `Bearer ${this.authorizationToken}`);
    headers.set(NO_ALIASING_HEADER, 'true');
    removeE2eeHeaders(headers);
    // Cloud API uses this routing-only header to select the verified NEAR
    // backend. It is deliberately not forwarded to the model request body.
    headers.set('x-model-pub-key', modelSigningPublicKey);
    return new Request(request, { headers });
  }

  private encryptSecureRequest({
    parsed,
    modelSigningPublicKey,
  }: EncryptSecureRequestParams): EncryptedSecureRequest {
    const clientKeyPair = createE2eeClientKeyPair();
    const encrypted = encryptE2eeChatRequest({
      body: parsed.body,
      modelSigningPublicKey,
    });
    const headers = new Headers(parsed.request.headers);
    // The serialized encrypted JSON has a different byte length from the
    // caller's body. Let Fetch calculate the new value.
    headers.delete('content-length');
    headers.set('authorization', `Bearer ${this.authorizationToken}`);
    headers.set('content-type', 'application/json');
    headers.set('x-signing-algo', 'ed25519');
    headers.set('x-client-pub-key', clientKeyPair.publicKey);
    headers.set('x-model-pub-key', modelSigningPublicKey);
    headers.set('x-encryption-version', '2');
    headers.set(NO_ALIASING_HEADER, 'true');
    headers.set('x-encrypt-all-fields', 'true');

    return {
      request: new Request(parsed.request, {
        headers,
        body: JSON.stringify(encrypted.body),
      }),
      clientKeyPair,
    };
  }

  private async sendCompletionRequest(request: Request): Promise<Response> {
    try {
      return await globalThis.fetch(request);
    } catch (cause) {
      throw new ApiError(
        {
          code: 'api.transport_failed',
          details: { resource: 'completion', reason: 'request' },
          retryable: true,
        },
        { cause },
      );
    }
  }

  private async decryptSecureResponse({
    response,
    clientKeyPair,
  }: DecryptSecureResponseParams): Promise<Response> {
    if (isServerSentEventResponse(response)) {
      return decryptSecureStreamResponse({ response, clientKeyPair });
    }
    const body = await decodeSecureResponseBody(response);
    const decrypted = decryptE2eeChatResponse({
      body,
      clientKeyPair,
    });
    const headers = new Headers(response.headers);
    headers.delete('content-length');
    headers.set('content-type', 'application/json');
    return new Response(JSON.stringify(decrypted), {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }
}

/** OpenAI-compatible verified Chat Completions client. */
export class NearAiSecureClient {
  readonly chat: SecureChat;
  readonly secure: SecureClient;

  constructor(options: NearAiSecureClientOptions) {
    this.secure = new SecureClient(options);
    this.chat = {
      completions: new NearAiSecureChatCompletions({
        secure: this.secure,
        authorizationToken: getAuthorizationToken(options),
      }),
    };
  }
}

type NearAiSecureChatCompletionsParams = {
  readonly secure: SecureClient;
  readonly authorizationToken: string;
};

class NearAiSecureChatCompletions implements SecureChatCompletions {
  readonly create: OpenAI.Chat.Completions['create'];
  private readonly authorizationToken: string;
  private readonly secure: SecureClient;

  constructor({
    secure,
    authorizationToken,
  }: NearAiSecureChatCompletionsParams) {
    this.secure = secure;
    this.authorizationToken = authorizationToken;
    const client = this.createOpenAiClient((input, init) =>
      this.secure.fetch(input, init),
    );
    this.create = client.chat.completions.create.bind(client.chat.completions);
  }

  async createWithReceipt(
    body: OpenAI.ChatCompletionCreateParamsNonStreaming,
    options?: OpenAI.RequestOptions,
  ): Promise<SecureChatCompletionWithReceipt>;
  async createWithReceipt(
    body: OpenAI.ChatCompletionCreateParamsStreaming,
    options?: OpenAI.RequestOptions,
  ): Promise<SecureChatCompletionStreamWithReceipt>;
  async createWithReceipt(
    body: OpenAiChatCompletionCreateParamsBase,
    options?: OpenAI.RequestOptions,
  ): Promise<
    SecureChatCompletionWithReceipt | SecureChatCompletionStreamWithReceipt
  >;
  async createWithReceipt(
    body: OpenAiChatCompletionCreateParamsBase,
    options?: OpenAI.RequestOptions,
  ): Promise<
    SecureChatCompletionWithReceipt | SecureChatCompletionStreamWithReceipt
  > {
    let captured: SecureFetchWithReceipt | undefined;
    const client = this.createOpenAiClient(async (input, init) => {
      const result = await this.secure.fetchWithReceipt(input, init);
      captured = result;
      return result.response;
    });
    const result = await client.chat.completions.create(body, options);
    if (captured === undefined) {
      throw new ApiError({
        code: 'api.invalid_response',
        details: {
          path: 'Chat Completions request',
          expected: 'one response from the secure transport',
          actual: 'no response',
        },
      });
    }

    if (body.stream === true) {
      return {
        stream: result as unknown as Stream<OpenAI.ChatCompletionChunk>,
        receipt: captured.receipt,
      };
    }
    return {
      completion: result as OpenAI.ChatCompletion,
      receipt: captured.receipt,
    };
  }

  private createOpenAiClient(fetch: typeof globalThis.fetch): OpenAI {
    return createOpenAiClient({
      authorizationToken: this.authorizationToken,
      baseUrl: this.secure.getBaseUrl(),
      fetch,
    });
  }
}

function createOpenAiClient({
  authorizationToken,
  baseUrl,
  fetch,
}: CreateOpenAiClientParams): OpenAI {
  return new OpenAI({
    apiKey: authorizationToken,
    baseURL: baseUrl,
    dangerouslyAllowBrowser: true,
    fetch,
    maxRetries: 0,
  });
}

function selectModelSigningPublicKey(
  attestations: readonly VerifiedModelAttestation[],
): string {
  for (const attestation of attestations) {
    const signingPublicKey = attestation.signingPublicKey;
    if (signingPublicKey !== undefined) {
      return signingPublicKey;
    }
  }
  throw new VerificationError({ code: 'e2ee.model_public_key_required' });
}

function createRequest(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
): Request {
  try {
    return new Request(input, init);
  } catch (cause) {
    throw new ApiError(
      {
        code: 'api.invalid_input',
        details: {
          field: 'request',
          reason: 'invalid_url',
          expected: 'a valid HTTP request',
        },
      },
      { cause },
    );
  }
}

async function decodeChatRequest({
  request,
}: DecodeChatRequestParams): Promise<unknown> {
  let text: string;
  try {
    text = await request.clone().text();
  } catch (cause) {
    throw invalidInput(
      {
        field: 'request body',
        reason: 'invalid_json',
        expected: 'a JSON Chat Completions request',
      },
      cause,
    );
  }
  try {
    return JSON.parse(text);
  } catch (cause) {
    throw invalidInput(
      {
        field: 'request body',
        reason: 'invalid_json',
        expected: 'a JSON Chat Completions request',
      },
      cause,
    );
  }
}

async function decodeSecureResponseBody(
  response: Response,
): Promise<SecureChatCompletionResponse> {
  let text: string;
  try {
    text = await response.text();
  } catch (cause) {
    throw new ApiError(
      {
        code: 'api.transport_failed',
        details: { resource: 'completion', reason: 'response_body' },
        retryable: true,
      },
      { cause },
    );
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (cause) {
    throw invalidSecureResponse(cause);
  }
  return parseE2eeChatResponse({ body: value });
}

type DecryptSecureStreamResponseParams = {
  readonly response: Response;
  readonly clientKeyPair: E2eeClientKeyPair;
};

function decryptSecureStreamResponse({
  response,
  clientKeyPair,
}: DecryptSecureStreamResponseParams): Response {
  if (response.body === null) {
    throw invalidSecureResponse();
  }
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  return new Response(
    response.body.pipeThrough(createE2eeChatSseTransform({ clientKeyPair })),
    {
      status: response.status,
      statusText: response.statusText,
      headers,
    },
  );
}

function captureRequestEntityBody(request: Request): Promise<Uint8Array> {
  const body = request
    .clone()
    .arrayBuffer()
    .then((body) => new Uint8Array(body));
  void body.catch(() => undefined);
  return body;
}

function captureResponseEntityBody(
  response: Response,
): CapturedResponseEntityBody {
  if (response.body === null) {
    return {
      response,
      responseBody: Promise.resolve(new Uint8Array()),
    };
  }

  let resolveBody: (body: Uint8Array) => void;
  let rejectBody: (cause: unknown) => void;
  const responseBody = new Promise<Uint8Array>((resolve, reject) => {
    resolveBody = resolve;
    rejectBody = reject;
  });
  // Receipt verification is optional. Preserve a rejection for a caller that
  // later awaits it without reporting an unhandled rejection in the meantime.
  void responseBody.catch(() => undefined);

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let settled = false;
  const resolve = (): void => {
    if (settled) return;
    try {
      const body = concatChunks(chunks);
      settled = true;
      resolveBody(body);
    } catch (cause) {
      reject(cause);
    }
  };
  const reject = (cause: unknown): void => {
    if (settled) return;
    settled = true;
    rejectBody(cause);
  };

  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const next = await reader.read();
        if (next.done) {
          resolve();
          controller.close();
          return;
        }
        chunks.push(next.value.slice());
        controller.enqueue(next.value);
      } catch (cause) {
        reject(cause);
        controller.error(cause);
      }
    },
    async cancel(reason) {
      if (
        hasSseCompletionSentinel({
          chunks,
          contentType: response.headers.get('content-type'),
        })
      ) {
        void drainResponseEntityBody({ reader, chunks, resolve, reject });
      } else {
        reject(reason);
        await reader.cancel(reason);
      }
    },
  });

  return {
    response: new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    }),
    responseBody,
  };
}

function concatChunks(chunks: readonly Uint8Array[]): Uint8Array {
  const length = chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

type GetCompletionIdParams = {
  readonly bytes: Uint8Array;
  readonly contentType: string | null;
};

function getCompletionId({
  bytes,
  contentType,
}: GetCompletionIdParams): string {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (cause) {
    throw invalidCompletionId(cause);
  }
  if (isServerSentEventContentType(contentType)) {
    return getSseCompletionId(text);
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (cause) {
    throw invalidCompletionId(cause);
  }
  return parseCompletionId(value);
}

function getSseCompletionId(text: string): string {
  for (const data of getSseDataRecords(text)) {
    if (data === '' || data === '[DONE]') {
      continue;
    }
    let value: unknown;
    try {
      value = JSON.parse(data);
    } catch (cause) {
      throw invalidCompletionId(cause);
    }
    const parsed = v.safeParse(CompletionResponseIdSchema, value);
    if (parsed.success) {
      return parsed.output.id;
    }
  }
  throw invalidCompletionId();
}

type HasSseCompletionSentinelParams = {
  readonly chunks: readonly Uint8Array[];
  readonly contentType: string | null;
};

function hasSseCompletionSentinel({
  chunks,
  contentType,
}: HasSseCompletionSentinelParams): boolean {
  if (!isServerSentEventContentType(contentType)) {
    return false;
  }
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(
      concatChunks(chunks),
    );
    return getSseDataRecords(text).some((data) => data === '[DONE]');
  } catch {
    return false;
  }
}

type DrainResponseEntityBodyParams = {
  readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  readonly chunks: Uint8Array[];
  readonly resolve: () => void;
  readonly reject: (cause: unknown) => void;
};

async function drainResponseEntityBody({
  reader,
  chunks,
  resolve,
  reject,
}: DrainResponseEntityBodyParams): Promise<void> {
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) {
        resolve();
        return;
      }
      chunks.push(next.value.slice());
    }
  } catch (cause) {
    reject(cause);
  }
}

function getSseDataRecords(text: string): string[] {
  return text.split(/\r\n\r\n|\n\n|\r\r/).map((record) =>
    record
      .split(/\r\n|\n|\r/)
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).replace(/^ /, ''))
      .join('\n'),
  );
}

function parseCompletionId(value: unknown): string {
  const parsed = v.safeParse(CompletionResponseIdSchema, value);
  if (!parsed.success) {
    throw invalidCompletionId();
  }
  return parsed.output.id;
}

function invalidCompletionId(cause?: unknown): ApiError {
  return new ApiError(
    {
      code: 'api.invalid_response',
      details: {
        path: 'Chat Completions response.id',
        expected: 'a non-empty completion ID',
        actual: 'missing or invalid',
      },
    },
    cause === undefined ? undefined : { cause },
  );
}

function isServerSentEventResponse(response: Response): boolean {
  return isServerSentEventContentType(response.headers.get('content-type'));
}

function isServerSentEventContentType(contentType: string | null): boolean {
  return contentType?.toLowerCase().startsWith('text/event-stream') ?? false;
}

function removeE2eeHeaders(headers: Headers): void {
  headers.delete('x-signing-algo');
  headers.delete('x-client-pub-key');
  headers.delete('x-model-pub-key');
  headers.delete('x-encryption-version');
  headers.delete('x-encrypt-all-fields');
}

function invalidInput(
  details: Extract<
    ApiError['failure'],
    { code: 'api.invalid_input' }
  >['details'],
  cause?: unknown,
): ApiError {
  return new ApiError(
    { code: 'api.invalid_input', details },
    cause === undefined ? undefined : { cause },
  );
}

function invalidSecureResponse(cause?: unknown): ApiError {
  return new ApiError(
    {
      code: 'api.invalid_response',
      details: {
        path: 'Chat Completions response',
        expected: 'an encrypted Chat Completions response',
        actual: 'invalid',
      },
    },
    cause === undefined ? undefined : { cause },
  );
}
