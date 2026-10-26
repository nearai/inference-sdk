// Messages support is deferred until a later release.
// import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import * as v from 'valibot';
import {
  ChatCompletionRequestSchema,
  CompletionResponseIdSchema,
} from '../schemas';
import type { SigningAlgo, SigningIdentity } from '../types/attestation-common';
import type { CompletionSignature } from '../types/chat';
import type {
  AttestationClientOptions,
  FetchCompletionSignatureParams,
  FetchedGatewayAttestation,
  FetchedModelAttestations,
  FetchModelAttestationsParams,
  ModelMetadata,
} from '../types/cloud-api';
import type { E2eeModelKey, PreparedE2eeChatRequest } from '../types/e2ee';
import type {
  AttestationVerificationResult,
  InferenceChat,
  InferenceClientCommonOptions,
  InferenceClientOptions,
  InferenceEncryptionOptions,
  // InferenceMessages,
  InferenceResponses,
  NodeInferenceClientOptions,
  VerifiedCompletionResult,
} from '../types/inference-client';
import type { OhttpAttestation } from '../types/ohttp';
import type { Awaitable } from '../types/shared';
import type { InferenceSystemOne } from '../types/systemone';
import type {
  ModelAttestationVerifiers,
  VerifiedModelAttestation,
} from '../types/verification';
import {
  ApiError,
  isApiError,
  isVerificationError,
  VerificationError,
} from '../utils/errors';
import {
  getSseDataRecords,
  getSseEvent,
  takeCompleteSseRecords,
} from '../utils/sse';
import { verifyGatewayAttestation } from './attestation-gateway';
import { verifyModelAttestation } from './attestation-model';
import { verifyGatewayResponse, verifyModelResponse } from './chat';
import type { CloudApiRequestConfiguration } from './cloud-api';
import {
  AttestationClient,
  CloudApiClient,
  createCloudApiRequestConfiguration,
  mergeCloudApiRequestHeaders,
  NO_ALIASING_HEADER,
  resolveCloudApiBaseUrl,
} from './cloud-api';
import {
  decodeChatRequest,
  isServerSentEventContentType,
  isServerSentEventResponse,
  prepareE2eeChatRequest,
  removeE2eeHeaders,
} from './e2ee-request';
import { verifyOhttpKeyConfig } from './ohttp-attestation';
import { createOhttpFetch } from './ohttp-fetch';
import { createSystemOne, sendSystemOne } from './systemone';

// OpenAI's client requires an API key even when a compatible aggregator uses
// another authentication header. `createOpenAiDefaultHeaders` removes this
// placeholder before the secure transport receives the request.
const OPENAI_WRAPPER_API_KEY = '@nearai/inference-sdk-internal';
const DEFAULT_CACHE_TIME_TO_LIVE_MS = 60 * 60 * 1000;

export type InferenceSession<
  VerificationResult,
  AttestationResult = unknown,
> = {
  readonly attestationResult: AttestationResult;
  /** Verified NEAR key for routing and encryption. Absent in Gateway-only sessions. */
  readonly modelKey?: E2eeModelKey;
  readonly transport: InferenceSessionTransport;
  readonly verifyResponse: (
    params: VerifySessionResponseParams,
  ) => Awaitable<VerificationResult>;
};

export type VerifySessionResponseParams = {
  readonly id: string;
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
  readonly signature: CompletionSignature;
};

export type InferenceSessionTransport = {
  readonly fetch: typeof globalThis.fetch;
  readonly fetchCompletionSignature: (
    params: FetchCompletionSignatureParams,
  ) => Promise<CompletionSignature>;
};

export type InferenceTransportOptions = InferenceClientCommonOptions &
  InferenceEncryptionOptions & {
    readonly baseUrl?: string;
    readonly apiKey?: string;
    readonly headers?: HeadersInit;
  };

type CachedVerification<VerificationResult, AttestationResult> = {
  readonly expiresAt: number;
  readonly session: InferenceSession<VerificationResult, AttestationResult>;
};

type CompletionProtocol = 'chat' | 'responses' | 'messages';

type ResponseRecord<VerificationResult> =
  VerifyCapturedResponseParams<VerificationResult> & {
    verification?: Promise<VerificationResult>;
    expiresAt?: number;
  };

type ParsedSecureRequest = {
  readonly model: string;
  readonly request: Request;
  readonly protocol: CompletionProtocol;
};

type PreparePlaintextRequestParams = {
  readonly request: Request;
  readonly modelKey?: E2eeModelKey;
  readonly messages?: boolean;
};

type SendSecureCompletionParams = {
  readonly input: RequestInfo | URL;
  readonly init?: RequestInit;
};

type SentSecureCompletion<VerificationResult> = {
  response: Response;
  readonly protocol: CompletionProtocol;
  readonly session: InferenceSession<VerificationResult>;
  readonly decryptResponse?: PreparedE2eeChatRequest['decryptResponse'];
};

type CapturedSecureCompletion<VerificationResult> =
  SentSecureCompletion<VerificationResult> & {
    readonly requestBody: Promise<Uint8Array>;
    readonly responseBody: Promise<Uint8Array>;
  };

type CapturedResponseEntityBody = {
  readonly response: Response;
  readonly responseBody: Promise<Uint8Array>;
};

export type VerifyCapturedResponseParams<VerificationResult> = {
  readonly id: string;
  readonly requestBody: Uint8Array;
  readonly responseBody: Promise<Uint8Array>;
  readonly session: InferenceSession<VerificationResult>;
  readonly gatewayOnly?: boolean;
};

type SendCompletionRequestParams = {
  readonly request: Request;
  readonly transport: InferenceSessionTransport;
};

type ClearPendingVerificationParams<VerificationResult> = {
  readonly cacheKey: string;
  readonly verification: Promise<InferenceSession<VerificationResult>>;
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

/** Internal Gateway operations used to fetch evidence and, after verification, send inference. */
type GatewaySessionTransport = {
  readonly fetch: typeof globalThis.fetch;
  readonly fetchModelMetadata: (model: string) => Promise<ModelMetadata>;
  readonly fetchModelAttestations: (
    params: FetchModelAttestationsParams,
  ) => Promise<FetchedModelAttestations>;
  readonly fetchCompletionSignature: (
    params: FetchCompletionSignatureParams,
  ) => Promise<CompletionSignature>;
};

type GatewaySessionEvidenceClientParams = {
  readonly options: AttestationClientOptions;
  readonly fetch: typeof globalThis.fetch;
  readonly signal: AbortSignal;
};

/** Session evidence requests share the transport and cancellation owned by preflight. */
class GatewaySessionEvidenceClient extends CloudApiClient {
  private readonly gatewayFetch: typeof globalThis.fetch;
  private readonly signal: AbortSignal;

  constructor({ options, fetch, signal }: GatewaySessionEvidenceClientParams) {
    super(options);
    this.gatewayFetch = fetch;
    this.signal = signal;
  }

  protected override requestCloudApi(request: Request): Promise<Response> {
    this.signal.throwIfAborted();
    return this.gatewayFetch(new Request(request, { signal: this.signal }));
  }
}

type VerifyModelsParams = {
  readonly model: string;
  readonly transport: GatewaySessionTransport;
  readonly signal: AbortSignal;
};

/**
 * A verified Chat Completions transport.
 *
 * Every `fetch()` call reads its model from the Chat request, then uses a
 * successfully verified session for that model when it remains
 * within the configured cache lifetime. With `e2ee: true`,
 * supported fields are encrypted to a quote-bound model key and
 * integrity-checked on the way back.
 * With E2EE disabled, Chat fields remain plaintext. Gateway clients verify
 * model evidence and route to a verified key for supported NEAR deployments;
 * Incognito models use Gateway verification only. Direct clients always
 * require model attestation.
 */
export abstract class VerifiedInferenceClientBase<
  VerificationResult,
  AttestationResult,
> {
  private readonly baseUrl: string;
  private readonly attestationCacheTimeToLiveMs: number;
  protected readonly e2eeEnabled: boolean;
  private readonly responseCacheTimeToLiveMs: number;
  private readonly responseRecords = new Map<
    string,
    ResponseRecord<VerificationResult>
  >();
  readonly chat: InferenceChat;
  protected readonly openai: OpenAI;
  protected readonly supportsGatewayEndpoints: boolean = false;
  protected readonly signingAlgo: SigningAlgo;
  protected readonly ohttpEnabled: boolean;
  private readonly options: InferenceTransportOptions;
  private readonly requestConfiguration: CloudApiRequestConfiguration;
  private readonly cachedVerifications = new Map<
    string,
    CachedVerification<VerificationResult, AttestationResult>
  >();
  /** Shares verification work for the same model while in progress. */
  private readonly pendingVerifications = new Map<
    string,
    Promise<InferenceSession<VerificationResult, AttestationResult>>
  >();

  protected constructor(options: InferenceTransportOptions) {
    this.baseUrl = resolveCloudApiBaseUrl(options.baseUrl);
    this.attestationCacheTimeToLiveMs =
      options.attestationCacheTimeToLiveMs ?? DEFAULT_CACHE_TIME_TO_LIVE_MS;
    this.e2eeEnabled = options.e2ee ?? false;
    this.signingAlgo = options.signingAlgo ?? 'ed25519';
    this.ohttpEnabled = options.ohttp ?? false;
    this.options = options;
    this.requestConfiguration = createCloudApiRequestConfiguration(options);
    this.responseCacheTimeToLiveMs =
      options.responseCacheTimeToLiveMs ?? DEFAULT_CACHE_TIME_TO_LIVE_MS;
    for (const [field, value] of [
      ['attestationCacheTimeToLiveMs', this.attestationCacheTimeToLiveMs],
      ['responseCacheTimeToLiveMs', this.responseCacheTimeToLiveMs],
    ] as const) {
      if (!Number.isFinite(value) || value < 0) {
        throw invalidInput({
          field,
          reason: 'unsupported_value',
          expected: 'a finite non-negative duration in milliseconds',
        });
      }
    }
    this.openai = createOpenAiClient({
      baseUrl: this.baseUrl,
      fetch: this.fetch,
      requestConfiguration: this.requestConfiguration,
    });
    this.chat = this.openai.chat;
  }

  /** Verify every required report before creating a session. */
  protected abstract createVerificationState(
    model: string,
  ): Promise<InferenceSession<VerificationResult, AttestationResult>>;

  /** Base URL to pair with this client's verified `fetch` implementation. */
  getBaseUrl(): string {
    return this.baseUrl;
  }

  /**
   * Verify the required attestations for a model and return the results without sending Chat.
   * Reuses the same cache and in-flight verification as Chat. With a cache
   * TTL of zero, a later Chat request verifies again.
   */
  async verify(model: string): Promise<AttestationResult> {
    if (model === '') {
      throw invalidInput({
        field: 'model',
        reason: 'missing_model',
        expected: 'a non-empty model ID',
      });
    }
    const session = await this.startVerification(model);
    return session.attestationResult;
  }

  /** Bind the advertised OHTTP key to the endpoint identity already verified. */
  protected getOhttpKeyConfig(
    ohttpAttestation: OhttpAttestation | undefined,
    signer: SigningIdentity,
  ): Uint8Array | undefined {
    if (!this.ohttpEnabled) return undefined;
    if (ohttpAttestation === undefined) {
      throw new VerificationError({ code: 'ohttp.attestation_required' });
    }
    return verifyOhttpKeyConfig({ ohttpAttestation, signer });
  }

  /** Inference creation uses OHTTP; evidence and signature fetches retain their transport. */
  protected createCompletionFetch(
    fetch: typeof globalThis.fetch,
    keyConfig: Uint8Array | undefined,
  ): typeof globalThis.fetch {
    return keyConfig === undefined
      ? fetch
      : createOhttpFetch({
          keyConfig,
          baseUrl: this.baseUrl,
          fetch,
          forwardedHeaders: [
            ...this.requestConfiguration.defaultHeaders.keys(),
          ],
        });
  }

  /**
   * Send one verified Chat Completions, Responses, or System One request.
   * Only POST requests to the configured creation endpoints are accepted.
   */
  readonly fetch = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const request = createRequest(input, init);
    const url = new URL(request.url);
    const systemOneUrl = new URL('systemone', this.baseUrl);
    if (
      request.method === 'POST' &&
      url.origin === systemOneUrl.origin &&
      url.pathname === systemOneUrl.pathname
    ) {
      return this.sendSystemOneRequest(request);
    }
    const completion = await this.sendSecureCompletion({
      input: request,
    });
    const requestBody = await completion.requestBody;
    const responseBody = completion.responseBody;

    if (completion.response.ok) {
      // Register before exposing the response, including its first SSE event.
      completion.response = registerCompletionResponse({
        response: completion.response,
        protocol: completion.protocol,
        register: (completionId) =>
          this.registerResponse({
            id: completionId,
            requestBody,
            responseBody,
            session: completion.session,
            gatewayOnly: completion.protocol !== 'chat',
          }),
      });
    }
    return this.toClientResponse(completion);
  };

  protected async sendSystemOneRequest(_request: Request): Promise<Response> {
    throw invalidInput({
      field: 'request',
      reason: 'unsupported_value',
      expected: 'a POST to the configured Chat Completions endpoint',
    });
  }

  /** Verify a captured response by ID. Consume streaming responses first. */
  verifyResponse(id: string): Promise<VerificationResult> {
    const record = this.getResponseRecord(id);
    if (record === undefined) {
      return Promise.reject(new ApiError({ code: 'api.completion_not_found' }));
    }
    record.verification ??= this.verifyCapturedResponse(record).catch(
      (cause: unknown) => {
        // Keep the captured bytes so a later call can retry a transient lookup.
        if (
          isApiError(cause) &&
          (cause.retryable ||
            cause.failure.code === 'api.completion_signature_unavailable')
        ) {
          record.verification = undefined;
        }
        throw cause;
      },
    );
    return record.verification;
  }

  /** All supported endpoints share byte retention, expiry, and verification retries. */
  protected registerResponse(record: ResponseRecord<VerificationResult>): void {
    if (this.responseCacheTimeToLiveMs === 0) return;
    const id = record.id;
    if (this.getResponseRecord(id) !== undefined) {
      throw new ApiError({ code: 'api.duplicate_completion_id' });
    }
    this.responseRecords.set(id, record);
    const expire = (): void => {
      const expiresAt = Date.now() + this.responseCacheTimeToLiveMs;
      record.expiresAt = expiresAt;
      const release = (): void => {
        if (this.responseRecords.get(id) !== record) return;
        const remaining = expiresAt - Date.now();
        if (remaining <= 0) {
          this.responseRecords.delete(id);
          return;
        }
        // JavaScript timers accept at most a signed 32-bit delay.
        const timer = setTimeout(release, Math.min(remaining, 2 ** 31 - 1));
        timer.unref?.();
      };
      release();
    };
    void record.responseBody.then(expire, expire);
  }

  private getResponseRecord(
    id: string,
  ): ResponseRecord<VerificationResult> | undefined {
    const record = this.responseRecords.get(id);
    if (record?.expiresAt !== undefined && record.expiresAt <= Date.now()) {
      this.responseRecords.delete(id);
      return undefined;
    }
    return record;
  }

  private async sendSecureCompletion({
    input,
    init,
  }: SendSecureCompletionParams): Promise<
    CapturedSecureCompletion<VerificationResult>
  > {
    const parsed = await this.parseSecureRequest(input, init);
    if (parsed.request.signal.aborted) {
      throw parsed.request.signal.reason;
    }
    const session = await awaitWithAbort({
      operation: this.startVerification(parsed.model),
      signal: parsed.request.signal,
    });

    if (this.e2eeEnabled && session.modelKey === undefined) {
      throw new VerificationError({
        code: 'policy.model_attestation_required',
      });
    }
    const prepared =
      this.e2eeEnabled && session.modelKey !== undefined
        ? await prepareE2eeChatRequest({
            request: new Request(parsed.request, {
              headers: this.createCompletionHeaders(parsed.request.headers),
            }),
            modelKey: session.modelKey,
          })
        : {
            request: this.preparePlaintextRequest({
              request: parsed.request,
              modelKey:
                parsed.protocol === 'messages' ? undefined : session.modelKey,
              messages: parsed.protocol === 'messages',
            }),
          };
    const decryptResponse =
      'decryptResponse' in prepared ? prepared.decryptResponse : undefined;

    const requestBody = captureRequestEntityBody(prepared.request);
    const response = await this.sendCompletionRequest({
      request: prepared.request,
      transport: session.transport,
    });
    const capturedResponse = captureResponseEntityBody(
      response,
      parsed.protocol,
    );
    return {
      response: capturedResponse.response,
      protocol: parsed.protocol,
      session,
      requestBody,
      responseBody: capturedResponse.responseBody,
      ...(decryptResponse === undefined ? {} : { decryptResponse }),
    };
  }

  private async toClientResponse({
    response,
    decryptResponse,
  }: SentSecureCompletion<VerificationResult>): Promise<Response> {
    return decryptResponse === undefined ? response : decryptResponse(response);
  }

  private async verifyCapturedResponse({
    id,
    requestBody,
    responseBody,
    session,
    gatewayOnly,
  }: VerifyCapturedResponseParams<VerificationResult>): Promise<VerificationResult> {
    const bytes = await responseBody;
    const signature = await session.transport.fetchCompletionSignature({
      completionId: id,
      signingAlgo: this.signingAlgo,
    });

    if (signature.signer.signingAlgo !== this.signingAlgo) {
      throw new VerificationError({ code: 'signature.signer_mismatch' });
    }
    if (gatewayOnly && signature.kind !== 'gateway') {
      throw new VerificationError({
        code: 'signature.kind_mismatch',
        details: { expected: 'gateway', actual: signature.kind },
      });
    }

    return session.verifyResponse({
      id,
      requestBody,
      responseBody: bytes,
      signature,
    });
  }

  protected startVerification(
    model: string,
  ): Promise<InferenceSession<VerificationResult, AttestationResult>> {
    const cacheKey = model;
    const now = Date.now();
    this.removeExpiredVerifications(now);
    const cached = this.cachedVerifications.get(cacheKey);
    if (this.attestationCacheTimeToLiveMs !== 0 && cached !== undefined) {
      return Promise.resolve(cached.session);
    }

    const existing = this.pendingVerifications.get(cacheKey);
    if (existing !== undefined) {
      return existing;
    }

    const verification = this.createVerificationState(model);
    this.pendingVerifications.set(cacheKey, verification);
    void verification.then(
      (session) => {
        if (this.attestationCacheTimeToLiveMs !== 0) {
          this.cachedVerifications.set(cacheKey, {
            expiresAt: Date.now() + this.attestationCacheTimeToLiveMs,
            session,
          });
        }
        this.clearPendingVerification({ cacheKey, verification });
      },
      () => this.clearPendingVerification({ cacheKey, verification }),
    );
    return verification;
  }

  private removeExpiredVerifications(now: number): void {
    for (const [cacheKey, cached] of this.cachedVerifications) {
      if (cached.expiresAt <= now) {
        this.cachedVerifications.delete(cacheKey);
      }
    }
  }

  private clearPendingVerification({
    cacheKey,
    verification,
  }: ClearPendingVerificationParams<VerificationResult>): void {
    if (this.pendingVerifications.get(cacheKey) === verification) {
      this.pendingVerifications.delete(cacheKey);
    }
  }

  protected getModelVerifiers(
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
    const protocol = this.requireSupportedEndpoint(request);
    const value = await decodeChatRequest({ request });
    const generic = v.safeParse(ChatCompletionRequestSchema, value);
    if (!generic.success) {
      throw invalidInput({
        field: 'request body',
        reason: 'unsupported_value',
        expected: 'a JSON inference request with a string model',
      });
    }
    const model = generic.output.model;
    return { model, request, protocol };
  }

  private requireSupportedEndpoint(request: Request): CompletionProtocol {
    const url = new URL(request.url);
    const baseUrl = new URL(this.baseUrl);
    const chatPath = new URL('chat/completions', this.baseUrl).pathname;
    const responses =
      url.pathname === new URL('responses', this.baseUrl).pathname;
    const messages =
      url.pathname === new URL('messages', this.baseUrl).pathname;
    if (
      request.method !== 'POST' ||
      url.origin !== baseUrl.origin ||
      (url.pathname !== chatPath &&
        // !((responses || messages) && this.supportsGatewayEndpoints))
        !(responses && this.supportsGatewayEndpoints))
    ) {
      throw invalidInput({
        field: 'request',
        reason: 'unsupported_value',
        expected: 'a POST to a supported inference creation endpoint',
        actual: `${request.method} ${url.pathname}`,
      });
    }
    if ((responses || messages) && this.e2eeEnabled) {
      throw invalidInput({
        field: 'e2ee',
        reason: 'unsupported_value',
        expected: 'field-level E2EE disabled for Responses',
      });
    }
    return messages ? 'messages' : responses ? 'responses' : 'chat';
  }

  private preparePlaintextRequest({
    request,
    modelKey,
    messages,
  }: PreparePlaintextRequestParams): Request {
    const headers = this.createCompletionHeaders(request.headers);
    headers.set(NO_ALIASING_HEADER, 'true');
    removeE2eeHeaders(headers);
    if (messages) {
      // External Anthropic clients may supply their own key. All inference and
      // evidence requests must use this client's configured authentication.
      const apiKey = this.requestConfiguration.defaultHeaders.get('x-api-key');
      if (apiKey === null) headers.delete('x-api-key');
      else headers.set('x-api-key', apiKey);
      if (!headers.has('anthropic-version')) {
        headers.set('anthropic-version', '2023-06-01');
      }
    }
    // Cloud API uses this routing-only header to select the verified NEAR
    // backend. It is deliberately not forwarded to the model request body.
    // X-Signing-Algo is an encryption header and requires a client key.
    if (modelKey !== undefined) {
      headers.set('x-model-pub-key', modelKey.publicKey);
    }
    return new Request(request, { headers });
  }

  private async sendCompletionRequest({
    request,
    transport,
  }: SendCompletionRequestParams): Promise<Response> {
    try {
      return await transport.fetch(request);
    } catch (cause) {
      if (isVerificationError(cause) || isApiError(cause)) {
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

  protected createCompletionHeaders(requestHeaders: HeadersInit): Headers {
    return mergeCloudApiRequestHeaders({
      configuration: this.requestConfiguration,
      requestHeaders,
    });
  }
}

/** Gateway-specific preflight layered over the shared Chat/E2EE transport. */
export abstract class InferenceClientBase extends VerifiedInferenceClientBase<
  VerifiedCompletionResult,
  AttestationVerificationResult
> {
  private readonly gatewayOptions: NodeInferenceClientOptions;
  protected override readonly supportsGatewayEndpoints = true;
  // private readonly anthropic: Anthropic;

  /** Create a Response, then verify its top-level ID with verifyResponse(). */
  get responses(): InferenceResponses {
    return this.openai.responses;
  }

  // /** Create a Message; verify its ID after consuming the response or stream. */
  // get messages(): InferenceMessages {
  //   return this.anthropic.messages;
  // }

  /** Send a decision request; pass result.decisionId to verifyResponse(). */
  readonly systemone: InferenceSystemOne = {
    create: async (request, options) =>
      createSystemOne({
        request,
        options,
        baseUrl: this.getBaseUrl(),
        encryptionEnabled: this.e2eeEnabled || this.ohttpEnabled,
        headers: this.createCompletionHeaders(options?.headers ?? {}),
        getSession: (model) => {
          const operation = this.startVerification(model);
          return options?.signal === undefined
            ? operation
            : awaitWithAbort({ operation, signal: options.signal });
        },
        registerResponse: (record) => this.registerResponse(record),
      }),
  };

  protected constructor(options: NodeInferenceClientOptions) {
    super(options);
    this.gatewayOptions = options;
    /* Messages support is deferred until a later release.
    this.anthropic = new Anthropic({
      apiKey: '@nearai/inference-sdk-internal',
      defaultHeaders: {
        'anthropic-version':
          new Headers(options.headers).get('anthropic-version') ?? '2023-06-01',
      },
      baseURL: this.getBaseUrl(),
      dangerouslyAllowBrowser: true,
      maxRetries: 0,
      fetch: (input, init) => {
        const request = new Request(input, init);
        const url = new URL(request.url);
        // Anthropic includes v1 in its resource path; our base already names
        // the API prefix. Adapt only this wrapper, preserving custom prefixes.
        const sdkUrl = new URL('v1/messages', this.getBaseUrl());
        if (url.origin === sdkUrl.origin && url.pathname === sdkUrl.pathname) {
          url.pathname = new URL('messages', this.getBaseUrl()).pathname;
        }
        return this.fetch(new Request(url, request));
      },
    });
    */
  }

  protected override sendSystemOneRequest(request: Request): Promise<Response> {
    return sendSystemOne({
      request,
      encryptionEnabled: this.e2eeEnabled || this.ohttpEnabled,
      headers: this.createCompletionHeaders(request.headers),
      // Official clients use Chat's selected-key routing contract for self-hosted models.
      getSession: (model) =>
        awaitWithAbort({
          operation: this.startVerification(model),
          signal: request.signal,
        }),
      registerResponse: (record) => this.registerResponse(record),
    });
  }

  protected abstract fetchGatewayAttestation(): Promise<FetchedGatewayAttestation>;

  protected abstract createGatewayFetch(
    peerSpkiFingerprint?: string,
  ): typeof globalThis.fetch;

  protected override async createVerificationState(
    model: string,
  ): Promise<
    InferenceSession<VerifiedCompletionResult, AttestationVerificationResult>
  > {
    const gateway = await this.fetchGatewayAttestation();
    // Pin evidence requests to the observed peer without treating it as trusted
    // yet. Gateway verification must authenticate that same fingerprint before
    // this session can be cached or used to send inference.
    const gatewayFetch = this.createGatewayFetch(
      gateway.clientBinding.spkiFingerprint,
    );
    const controller = new AbortController();
    const { signal } = controller;
    const client = new GatewaySessionEvidenceClient({
      options: this.gatewayOptions,
      fetch: gatewayFetch,
      signal,
    });
    const transport: GatewaySessionTransport = {
      fetch: gatewayFetch,
      fetchModelMetadata: (model) => client.fetchModelMetadata(model),
      fetchModelAttestations: (params) => client.fetchModelAttestations(params),
      fetchCompletionSignature: (params) =>
        client.fetchCompletionSignature(params),
    };
    const [{ gatewayAttestation, ohttpKeyConfig }, modelAttestations] =
      await Promise.all([
        verifyGatewayAttestation({
          attestation: gateway.attestation,
          clientBinding: gateway.clientBinding,
          policy: this.gatewayOptions.gatewayVerification?.policy,
          verifiers: this.gatewayOptions.gatewayVerification?.verifiers,
        }).then((gatewayAttestation) => {
          signal.throwIfAborted();
          if (gatewayAttestation.signer.signingAlgo !== this.signingAlgo) {
            throw new VerificationError({ code: 'signature.signer_mismatch' });
          }
          return {
            gatewayAttestation,
            ohttpKeyConfig: this.getOhttpKeyConfig(
              gateway.attestation.ohttpAttestation,
              gatewayAttestation.signer,
            ),
          };
        }),
        this.verifyModels({ model, transport, signal }),
      ]).catch((cause: unknown) => {
        // Cancel outstanding evidence I/O before a retry can start a new preflight.
        // Keep the original failure instead of replacing it with an abort error.
        controller.abort(cause);
        throw cause;
      });
    const modelAttestation = modelAttestations.find(
      (attestation) =>
        attestation.signer.signingAlgo === this.signingAlgo &&
        attestation.signingPublicKey !== undefined,
    );
    if (modelAttestations.length > 0 && modelAttestation === undefined) {
      throw new VerificationError({ code: 'e2ee.model_public_key_required' });
    }
    const modelKey =
      modelAttestation?.signingPublicKey !== undefined
        ? {
            signingAlgo: this.signingAlgo,
            publicKey: modelAttestation.signingPublicKey,
          }
        : undefined;
    return {
      attestationResult: {
        gateway: gatewayAttestation,
        models: modelAttestations,
        verifiedAt: Date.now(),
      },
      modelKey,
      transport: {
        ...transport,
        fetch: this.createCompletionFetch(transport.fetch, ohttpKeyConfig),
      },
      verifyResponse: ({ id, requestBody, responseBody, signature }) => {
        if (signature.kind === 'provider_tee') {
          if (modelAttestation === undefined) {
            throw new VerificationError({
              code: 'signature.kind_mismatch',
              details: { expected: 'gateway', actual: signature.kind },
            });
          }
          verifyModelResponse({
            requestBody,
            responseBody,
            signature,
            attestation: modelAttestation,
          });
          return {
            id,
            completionId: id,
            signatureKind: 'provider_tee',
            signature,
            attestation: modelAttestation,
          };
        }
        verifyGatewayResponse({
          requestBody,
          responseBody,
          signature,
          attestation: gatewayAttestation,
        });
        return {
          id,
          completionId: id,
          signatureKind: 'gateway',
          signature,
          attestation: gatewayAttestation,
        };
      },
    };
  }

  /** NEAR deployments use model evidence; Incognito sessions verify only the Gateway. */
  private async verifyModels({
    model,
    transport,
    signal,
  }: VerifyModelsParams): Promise<VerifiedModelAttestation[]> {
    const metadata = await transport.fetchModelMetadata(model);
    signal.throwIfAborted();
    if (metadata.providerType !== 'vllm' || !metadata.attestationSupported) {
      const { deploymentPolicy, modelVerification } = this.gatewayOptions;
      if (
        this.e2eeEnabled ||
        deploymentPolicy !== undefined ||
        modelVerification?.policy !== undefined ||
        modelVerification?.verifiers?.deployment !== undefined
      ) {
        throw new VerificationError({
          code: 'policy.model_attestation_required',
        });
      }
      return [];
    }

    const fetchedModels = await transport.fetchModelAttestations({
      model,
      signingAlgo: this.signingAlgo,
    });
    signal.throwIfAborted();
    if (fetchedModels.attestations.length === 0) {
      throw new VerificationError({
        code: 'policy.model_attestation_required',
      });
    }
    const modelVerifiers = this.getModelVerifiers(model);
    const attestations = await Promise.all(
      fetchedModels.attestations.map((attestation) =>
        verifyModelAttestation({
          attestation,
          clientBinding: fetchedModels.clientBinding,
          policy: this.gatewayOptions.modelVerification?.policy,
          verifiers: modelVerifiers,
        }),
      ),
    );
    return attestations;
  }
}

/** Browser-compatible verified Chat Completions transport. */
export class InferenceClient extends InferenceClientBase {
  private readonly attestationClient: AttestationClient;

  constructor(options: InferenceClientOptions) {
    super(options);
    this.attestationClient = new AttestationClient(options);
  }

  protected override fetchGatewayAttestation(): Promise<FetchedGatewayAttestation> {
    return this.attestationClient.fetchGatewayAttestation({
      signingAlgo: this.signingAlgo,
      includeSpkiFingerprint: false,
    });
  }

  protected override createGatewayFetch(): typeof globalThis.fetch {
    return globalThis.fetch.bind(globalThis);
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
    maxRetries: 0,
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

type RegisterCompletionResponseParams = {
  readonly response: Response;
  readonly protocol: CompletionProtocol;
  readonly register: (id: string) => void;
};

/** Register IDs before forwarding their bytes; streaming follows consumer backpressure. */
function registerCompletionResponse({
  response,
  protocol,
  register,
}: RegisterCompletionResponseParams): Response {
  if (response.body === null) return response;
  const streaming = isServerSentEventResponse(response);
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let pending = '';
  let registered = false;
  const body = response.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        if (!registered) {
          pending += decoder.decode(chunk, { stream: true });
          if (streaming) {
            const complete = takeCompleteSseRecords(pending);
            pending = complete.pending;
            for (const record of complete.records) {
              let id: string;
              try {
                id = getSseCompletionId(record.value, protocol);
              } catch {
                continue;
              }
              register(id);
              registered = true;
              pending = '';
              break;
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
              ? getSseCompletionId(pending, protocol)
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
  protocol: CompletionProtocol,
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
  // Response verification is optional. Preserve a rejection for a caller that
  // later awaits it without reporting an unhandled rejection in the meantime.
  void responseBody.catch(() => undefined);

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let settled = false;
  const resolve = (): void => {
    if (settled) return;
    try {
      const body = concatChunks(chunks);
      if (
        response.ok &&
        protocol === 'messages' &&
        isServerSentEventResponse(response)
      ) {
        validateMessageStream(body);
      }
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
          protocol,
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

function getSseCompletionId(
  text: string,
  protocol: CompletionProtocol,
): string {
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
    if (protocol === 'responses') {
      value =
        value !== null && typeof value === 'object' && 'response' in value
          ? value.response
          : undefined;
    }
    if (protocol === 'messages') {
      value =
        value !== null &&
        typeof value === 'object' &&
        'type' in value &&
        value.type === 'message_start' &&
        'message' in value
          ? value.message
          : undefined;
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
  readonly protocol: CompletionProtocol;
};

function hasSseCompletionSentinel({
  chunks,
  contentType,
  protocol,
}: HasSseCompletionSentinelParams): boolean {
  if (!isServerSentEventContentType(contentType)) {
    return false;
  }
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(
      concatChunks(chunks),
    );
    if (protocol === 'messages') {
      validateMessageStream(concatChunks(chunks));
      return true;
    }
    return getSseDataRecords(text).some((data) => data === '[DONE]');
  } catch {
    return false;
  }
}

/** EOF or a tool block alone cannot complete a signed Messages stream. */
function validateMessageStream(body: Uint8Array): void {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(body);
  const { records, pending } = takeCompleteSseRecords(text, true);
  let id: string | undefined;
  let stopped = false;
  if (pending !== '') throw invalidCompletionId();
  for (const record of records) {
    const eventName = getSseEvent(record.value);
    if (eventName === 'error') throw invalidCompletionId();
    for (const data of getSseDataRecords(record.value)) {
      if (data === '') continue;
      let event: { type?: unknown };
      try {
        event = JSON.parse(data);
      } catch {
        throw invalidCompletionId();
      }
      if (
        typeof event?.type !== 'string' ||
        event.type === '' ||
        event.type === 'error' ||
        stopped ||
        (eventName !== undefined && eventName !== event?.type)
      )
        throw invalidCompletionId();
      if (event?.type === 'message_start') {
        if (id !== undefined) throw invalidCompletionId();
        id = getSseCompletionId(record.value, 'messages');
      }
      if (event?.type === 'message_stop') stopped = true;
    }
  }
  if (id === undefined || !stopped) throw invalidCompletionId();
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
        path: 'completion response ID or SSE lifecycle',
        expected: 'a non-empty ID and a complete valid stream',
        actual: 'missing or invalid',
      },
    },
    cause === undefined ? undefined : { cause },
  );
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
