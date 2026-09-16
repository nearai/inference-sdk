import OpenAI from 'openai';
import * as v from 'valibot';
import {
  ChatCompletionRequestSchema,
  CompletionResponseIdSchema,
} from '../schemas';
import type {
  GatewayTlsBinding,
  ModelAttestationVerifiers,
  VerifiedGatewayAttestation,
  VerifiedModelAttestation,
} from '../types/verification';
import type { SigningAlgo } from '../types/attestation-common';
import type {
  FetchCompletionSignatureParams,
  FetchedGatewayAttestation,
  FetchedModelAttestations,
  FetchModelAttestationsParams,
} from '../types/cloud-api';
import type { CompletionSignature } from '../types/chat';
import type {
  NodeSecureClientOptions,
  SecureChat,
  SecureChatCompletionRequest,
  SecureChatCompletionResponse,
  SecureClientOptions,
  VerifiedCompletionReceipt,
} from '../types/secure-client';
import {
  ApiError,
  isApiError,
  isVerificationError,
  VerificationError,
} from '../utils/errors';
import {
  AttestationClient,
  createCloudApiRequestConfiguration,
  mergeCloudApiRequestHeaders,
  NO_ALIASING_HEADER,
  resolveCloudApiBaseUrl,
} from './cloud-api';
import type { CloudApiRequestConfiguration } from './cloud-api';
import { verifyGatewayAttestation } from './attestation-gateway';
import { verifyModelAttestation } from './attestation-model';
import { verifyGatewayResponse, verifyModelResponse } from './chat';
import {
  createE2eeChatSseTransform,
  decryptE2eeChatResponse,
  encryptE2eeChatRequest,
  parseE2eeChatResponse,
} from './e2ee-chat';
import {
  createE2eeClientKeyPair,
  type E2eeClientKeyPair,
  type E2eeModelKey,
} from './e2ee';

// OpenAI's client requires an API key even when a compatible aggregator uses
// another authentication header. `createOpenAiDefaultHeaders` removes this
// placeholder before the secure transport receives the request.
const OPENAI_WRAPPER_API_KEY = '@nearai/inference-sdk-internal';
const DEFAULT_CACHE_TIME_TO_LIVE_MS = 60 * 60 * 1000;

type SecureSessionState = {
  readonly gatewayAttestation: VerifiedGatewayAttestation;
  readonly modelAttestation: VerifiedModelAttestation;
  readonly modelKey: E2eeModelKey;
  readonly transport: GatewaySessionTransport;
};

type CachedVerification = {
  readonly expiresAt: number;
  readonly session: SecureSessionState;
};

type CompletionRecord = VerifyCapturedCompletionParams & {
  verification?: Promise<VerifiedCompletionReceipt>;
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
  readonly modelKey: E2eeModelKey;
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
  readonly modelKey: E2eeModelKey;
};

type SendSecureCompletionParams = {
  readonly input: RequestInfo | URL;
  readonly init?: RequestInit;
};

type SentSecureCompletion = {
  response: Response;
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

type SendCompletionRequestParams = {
  readonly request: Request;
  readonly transport: GatewaySessionTransport;
};

type ClearPendingVerificationParams = {
  readonly model: string;
  readonly verification: Promise<SecureSessionState>;
};

type AwaitWithAbortParams<T> = {
  readonly operation: Promise<T>;
  readonly signal: AbortSignal;
};

type CreateOpenAiClientParams = {
  readonly baseUrl: string;
  readonly fetch: typeof globalThis.fetch;
  readonly requestConfiguration: CloudApiRequestConfiguration;
};

/** Internal request operations bound to one verified Gateway session. */
export type GatewaySessionTransport = {
  readonly fetch: typeof globalThis.fetch;
  readonly fetchModelAttestations: (
    params: FetchModelAttestationsParams,
  ) => Promise<FetchedModelAttestations>;
  readonly fetchCompletionSignature: (
    params: FetchCompletionSignatureParams,
  ) => Promise<CompletionSignature>;
};

/** Parameters used to create an internal Gateway session transport. */
export type CreateGatewaySessionTransportParams = {
  readonly tlsBinding: GatewayTlsBinding;
};

/**
 * A verified Chat Completions transport.
 *
 * Every `fetch()` call reads its model from the Chat request, then uses a
 * successfully verified Gateway/model session for that model when it remains
 * within the configured cache lifetime. With the default `e2ee: true`,
 * supported fields are encrypted to a quote-bound model key and
 * integrity-checked on the way back.
 * With `e2ee: false`, the same evidence and policy checks run on a cache miss,
 * but the Chat request and response remain plaintext while the request stays
 * pinned to the verified model key.
 */
export abstract class SecureClientBase {
  private readonly baseUrl: string;
  private readonly attestationCacheTimeToLiveMs: number;
  private readonly e2eeEnabled: boolean;
  private readonly responseCacheTimeToLiveMs: number;
  private readonly completions = new Map<string, CompletionRecord>();
  readonly chat: SecureChat;
  protected readonly signingAlgo: SigningAlgo;
  private readonly options: NodeSecureClientOptions;
  private readonly requestConfiguration: CloudApiRequestConfiguration;
  private readonly cachedVerifications = new Map<string, CachedVerification>();
  /** Shares same-model verification work while it is in progress. */
  private readonly pendingVerifications = new Map<
    string,
    Promise<SecureSessionState>
  >();

  protected constructor(options: NodeSecureClientOptions) {
    this.baseUrl = resolveCloudApiBaseUrl(options.baseUrl);
    this.attestationCacheTimeToLiveMs =
      options.attestationCacheTimeToLiveMs ?? DEFAULT_CACHE_TIME_TO_LIVE_MS;
    this.e2eeEnabled = options.e2ee !== false;
    this.signingAlgo = options.signingAlgo ?? 'ed25519';
    this.options = options;
    this.requestConfiguration = createCloudApiRequestConfiguration(options);
    this.responseCacheTimeToLiveMs =
      options.responseCacheTimeToLiveMs ?? DEFAULT_CACHE_TIME_TO_LIVE_MS;
    this.chat = createOpenAiClient({
      baseUrl: this.baseUrl,
      fetch: this.fetch,
      requestConfiguration: this.requestConfiguration,
    }).chat;
  }

  /** Fetch Gateway evidence when starting a new verification session. */
  protected abstract fetchGatewayAttestation(): Promise<FetchedGatewayAttestation>;

  /** Create the request transport for one successfully verified Gateway. */
  protected abstract createGatewaySessionTransport(
    params: CreateGatewaySessionTransportParams,
  ): GatewaySessionTransport;

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
  readonly fetch = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const completion = await this.sendSecureCompletion({
      input,
      init,
    });
    const requestBody = await completion.requestBody;
    const responseBody = completion.responseBody;

    if (completion.response.ok) {
      const record: CompletionRecord = {
        requestBody,
        responseBody,
        session: completion.session,
        contentType: completion.response.headers.get('content-type'),
      };
      // Register before exposing the response, including its first SSE event.
      completion.response = registerCompletionResponse({
        response: completion.response,
        register: (id) => {
          this.completions.set(id, record);
          const expire = (): void => {
            const timer = setTimeout(() => {
              if (this.completions.get(id) === record)
                this.completions.delete(id);
            }, this.responseCacheTimeToLiveMs);
            timer.unref?.();
          };
          void responseBody.then(expire, expire);
        },
      });
    }
    return this.toClientResponse(completion);
  };

  /** Verify a captured response by ID. Consume streaming responses first. */
  verifyResponse(completionId: string): Promise<VerifiedCompletionReceipt> {
    const record = this.completions.get(completionId);
    if (record === undefined) {
      return Promise.reject(new ApiError({ code: 'api.completion_not_found' }));
    }
    record.verification ??= this.verifyCapturedCompletion(record).catch(
      (cause: unknown) => {
        // Keep the captured bytes so a later call can retry a transient lookup.
        if (isApiError(cause) && cause.retryable) {
          record.verification = undefined;
        }
        throw cause;
      },
    );
    return record.verification;
  }

  private async sendSecureCompletion({
    input,
    init,
  }: SendSecureCompletionParams): Promise<CapturedSecureCompletion> {
    const parsed = await this.parseSecureRequest(input, init);
    if (parsed.request.signal.aborted) {
      throw parsed.request.signal.reason;
    }
    const session = await awaitWithAbort({
      operation: this.startVerification(parsed.model),
      signal: parsed.request.signal,
    });

    const prepared = parsed.e2ee
      ? this.encryptSecureRequest({
          parsed,
          modelKey: session.modelKey,
        })
      : {
          request: this.preparePlaintextRequest({
            request: parsed.request,
            modelKey: session.modelKey,
          }),
        };
    const clientKeyPair =
      'clientKeyPair' in prepared ? prepared.clientKeyPair : undefined;

    const requestBody = captureRequestEntityBody(prepared.request);
    const response = await this.sendCompletionRequest({
      request: prepared.request,
      transport: session.transport,
    });
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

  private async verifyCapturedCompletion({
    requestBody,
    responseBody,
    session,
    contentType,
  }: VerifyCapturedCompletionParams): Promise<VerifiedCompletionReceipt> {
    const bytes = await responseBody;
    const completionId = getCompletionId({ bytes, contentType });
    const signature = await session.transport.fetchCompletionSignature({
      completionId,
      signingAlgo: session.modelKey.signingAlgo,
    });

    if (signature.kind === 'provider_tee') {
      const attestation = session.modelAttestation;
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
    } else {
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
  }

  private startVerification(model: string): Promise<SecureSessionState> {
    const now = Date.now();
    this.removeExpiredVerifications(now);
    const cached = this.cachedVerifications.get(model);
    if (this.attestationCacheTimeToLiveMs !== 0 && cached !== undefined) {
      return Promise.resolve(cached.session);
    }

    const existing = this.pendingVerifications.get(model);
    if (existing !== undefined) {
      return existing;
    }

    const verification = this.createVerificationState(model);
    this.pendingVerifications.set(model, verification);
    void verification.then(
      (session) => {
        if (this.attestationCacheTimeToLiveMs !== 0) {
          this.cachedVerifications.set(model, {
            expiresAt: Date.now() + this.attestationCacheTimeToLiveMs,
            session,
          });
        }
        this.clearPendingVerification({ model, verification });
      },
      () => this.clearPendingVerification({ model, verification }),
    );
    return verification;
  }

  private removeExpiredVerifications(now: number): void {
    for (const [model, cached] of this.cachedVerifications) {
      if (cached.expiresAt <= now) {
        this.cachedVerifications.delete(model);
      }
    }
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
    const gateway = await this.fetchGatewayAttestation();
    const gatewayAttestation = await verifyGatewayAttestation({
      attestation: gateway.attestation,
      clientBinding: gateway.clientBinding,
      policy: this.options.gatewayVerification?.policy,
      verifiers: this.options.gatewayVerification?.verifiers,
    });
    const transport = this.createGatewaySessionTransport({
      tlsBinding: gatewayAttestation.tlsBinding,
    });
    const fetchedModels = await transport.fetchModelAttestations({
      model,
      signingAlgo: this.signingAlgo,
    });
    if (fetchedModels.attestations.length === 0) {
      throw new VerificationError({
        code: 'policy.model_attestation_required',
      });
    }

    const modelVerifiers = this.getModelVerifiers(model);
    const modelAttestations = await Promise.all(
      fetchedModels.attestations.map((attestation) =>
        verifyModelAttestation({
          attestation,
          clientBinding: fetchedModels.clientBinding,
          policy: this.options.modelVerification?.policy,
          verifiers: modelVerifiers,
        }),
      ),
    );
    const modelAttestation = modelAttestations.find(
      (attestation) =>
        attestation.signer.signingAlgo === this.signingAlgo &&
        attestation.signingPublicKey !== undefined,
    );
    if (modelAttestation?.signingPublicKey === undefined) {
      throw new VerificationError({ code: 'e2ee.model_public_key_required' });
    }

    return {
      gatewayAttestation,
      modelAttestation,
      modelKey: {
        signingAlgo: this.signingAlgo,
        publicKey: modelAttestation.signingPublicKey,
      },
      transport,
    };
  }

  private getModelVerifiers(
    model: string,
  ): ModelAttestationVerifiers | undefined {
    const verifiers = this.options.modelVerification?.verifiers;
    const deploymentPolicy = this.options.deploymentPolicy;
    if (deploymentPolicy === undefined) {
      return verifiers;
    }
    return {
      ...verifiers,
      deployment: async (deployment) => {
        await verifiers?.deployment?.(deployment);
        await deploymentPolicy({ model, deployment });
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
    modelKey,
  }: PreparePlaintextRequestParams): Request {
    const headers = this.createCompletionHeaders(request.headers);
    headers.set(NO_ALIASING_HEADER, 'true');
    removeE2eeHeaders(headers);
    // Cloud API uses this routing-only header to select the verified NEAR
    // backend. It is deliberately not forwarded to the model request body.
    // X-Signing-Algo is an encryption header and requires a client key.
    headers.set('x-model-pub-key', modelKey.publicKey);
    return new Request(request, { headers });
  }

  private encryptSecureRequest({
    parsed,
    modelKey,
  }: EncryptSecureRequestParams): EncryptedSecureRequest {
    const clientKeyPair = createE2eeClientKeyPair(modelKey.signingAlgo);
    const encrypted = encryptE2eeChatRequest({
      body: parsed.body,
      modelKey,
    });
    const headers = this.createCompletionHeaders(parsed.request.headers);
    // The serialized encrypted JSON has a different byte length from the
    // caller's body. Let Fetch calculate the new value.
    headers.delete('content-length');
    headers.set('content-type', 'application/json');
    removeE2eeHeaders(headers);
    headers.set('x-signing-algo', modelKey.signingAlgo);
    headers.set('x-client-pub-key', clientKeyPair.publicKey);
    headers.set('x-model-pub-key', modelKey.publicKey);
    if (modelKey.signingAlgo === 'ed25519') {
      headers.set('x-encryption-version', '2');
    }
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

  private async sendCompletionRequest({
    request,
    transport,
  }: SendCompletionRequestParams): Promise<Response> {
    try {
      return await transport.fetch(request);
    } catch (cause) {
      if (isVerificationError(cause)) {
        throw cause;
      }
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

  private createCompletionHeaders(requestHeaders: HeadersInit): Headers {
    return mergeCloudApiRequestHeaders({
      configuration: this.requestConfiguration,
      requestHeaders,
    });
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

/** Browser-compatible verified Chat Completions transport. */
export class SecureClient extends SecureClientBase {
  private readonly attestationClient: AttestationClient;

  constructor(options: SecureClientOptions) {
    super(options);
    this.attestationClient = new AttestationClient(options);
  }

  protected override fetchGatewayAttestation(): Promise<FetchedGatewayAttestation> {
    return this.attestationClient.fetchGatewayAttestation({
      signingAlgo: this.signingAlgo,
      includeSpkiFingerprint: false,
    });
  }

  protected override createGatewaySessionTransport(
    _params: CreateGatewaySessionTransportParams,
  ): GatewaySessionTransport {
    return {
      fetch: globalThis.fetch.bind(globalThis),
      fetchModelAttestations: (params) =>
        this.attestationClient.fetchModelAttestations(params),
      fetchCompletionSignature: (params) =>
        this.attestationClient.fetchCompletionSignature(params),
    };
  }
}

function createOpenAiClient({
  baseUrl,
  fetch,
  requestConfiguration,
}: CreateOpenAiClientParams): OpenAI {
  return new OpenAI({
    apiKey: requestConfiguration.apiKey ?? OPENAI_WRAPPER_API_KEY,
    baseURL: baseUrl,
    dangerouslyAllowBrowser: true,
    defaultHeaders: createOpenAiDefaultHeaders(requestConfiguration),
    fetch,
  });
}

function createOpenAiDefaultHeaders(
  requestConfiguration: CloudApiRequestConfiguration,
): Record<string, string | null> {
  const headers: Record<string, string | null> = {};
  for (const [name, value] of requestConfiguration.defaultHeaders) {
    headers[name] = value;
  }
  if (requestConfiguration.apiKey !== undefined) {
    delete headers.authorization;
    delete headers['api-key'];
  } else if (!requestConfiguration.defaultHeaders.has('authorization')) {
    // OpenAI's wrapper requires an explicit authentication decision even when
    // an aggregator uses a different header name.
    headers.authorization = null;
  }
  return headers;
}

function awaitWithAbort<T>({
  operation,
  signal,
}: AwaitWithAbortParams<T>): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(signal.reason);
  }
  return new Promise((resolve, reject) => {
    const abort = (): void => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
    void operation.then(
      (value) => {
        signal.removeEventListener('abort', abort);
        resolve(value);
      },
      (cause: unknown) => {
        signal.removeEventListener('abort', abort);
        reject(cause);
      },
    );
  });
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
  request.signal.throwIfAborted();
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  const decoder = new TextDecoder();
  let text = '';
  try {
    reader = request.clone().body?.getReader();
    if (reader !== undefined) {
      while (true) {
        const chunk = await awaitWithAbort({
          operation: reader.read(),
          signal: request.signal,
        });
        if (chunk.done) break;
        text += decoder.decode(chunk.value, { stream: true });
      }
      text += decoder.decode();
    }
    return JSON.parse(text);
  } catch (cause) {
    if (request.signal.aborted) {
      // Cancelling a cloned stream may wait for the caller's other branch.
      // Stop our reader without delaying the abort result on that branch.
      void reader?.cancel(request.signal.reason).catch(() => undefined);
      throw request.signal.reason;
    }
    throw invalidInput(
      {
        field: 'request body',
        reason: 'invalid_json',
        expected: 'a JSON Chat Completions request',
      },
      cause,
    );
  } finally {
    reader?.releaseLock();
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

type RegisterCompletionResponseParams = {
  readonly response: Response;
  readonly register: (id: string) => void;
};

/** Register IDs before forwarding their bytes; streaming follows consumer backpressure. */
function registerCompletionResponse({
  response,
  register,
}: RegisterCompletionResponseParams): Response {
  if (response.body === null) return response;
  const streaming = isServerSentEventResponse(response);
  const decoder = new TextDecoder();
  let pending = '';
  let registered = false;
  const body = response.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        if (!registered) {
          pending += decoder.decode(chunk, { stream: true });
          if (streaming) {
            const records = getSseDataRecords(pending);
            for (const data of records.slice(0, -1)) {
              if (data === '' || data === '[DONE]') continue;
              let value: unknown;
              try {
                value = JSON.parse(data);
              } catch {
                continue;
              }
              const parsed = v.safeParse(CompletionResponseIdSchema, value);
              if (parsed.success) {
                register(parsed.output.id);
                registered = true;
                pending = '';
                break;
              }
            }
          }
        }
        controller.enqueue(chunk);
      },
      flush() {
        if (!registered) {
          pending += decoder.decode();
          let id: string;
          try {
            id = streaming
              ? getSseCompletionId(pending)
              : parseCompletionId(JSON.parse(pending));
          } catch (cause) {
            throw invalidCompletionId(cause);
          }
          register(id);
        }
      },
    }),
  );
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
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
  return text.split(/(?:\r\n|\n|\r)(?:\r\n|\n|\r)/).map((record) =>
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
