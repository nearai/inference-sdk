import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import * as v from 'valibot';
import {
  ChatCompletionRequestSchema,
  CompletionResponseIdSchema,
} from '../schemas';
import type { SigningAlgo, SigningIdentity } from '../types/attestation-common';
import type { CompletionSignature } from '../types/chat';
import type {
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
  InferenceMessages,
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
  getSseEvent,
  getSseRecordData,
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
  findModelAttestationsForSignature,
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

type ResponseRecord<VerificationResult> = {
  captured?: VerifyCapturedResponseParams<VerificationResult>;
  verification?: Promise<VerificationResult>;
  expiresAt?: number;
  expiry?: ReturnType<typeof setTimeout>;
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

type CapturedSecureCompletion<VerificationResult> = {
  readonly response: Response;
  readonly protocol: CompletionProtocol;
  readonly session: InferenceSession<VerificationResult>;
  readonly decryptJsonResponse?: PreparedE2eeChatRequest['decryptResponse'];
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

type VerifyModelAttestationsParams = {
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
  protected responseCacheGeneration = 0;
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

  /** Verify the required deployment attestations before sending a prompt. */
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
   * Send one verified Chat Completions, Responses, Messages, or System One request.
   * Only POST requests to the configured creation endpoints are accepted.
   */
  readonly fetch = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const generation = this.responseCacheGeneration;
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

    if (!completion.response.ok) return completion.response;
    const register = (id: string) =>
      this.registerResponse(
        {
          id,
          requestBody,
          responseBody,
          session: completion.session,
          gatewayOnly: completion.protocol !== 'chat',
        },
        generation,
      );
    const decryptJson = completion.decryptJsonResponse;
    let jsonId: string | undefined;
    const response = registerCompletionResponse({
      response: completion.response,
      protocol: completion.protocol,
      register: decryptJson
        ? (id) => {
            jsonId = id;
          }
        : register,
    });
    if (!decryptJson) return response;
    const decrypted = await decryptJson(response);
    if (jsonId !== undefined) register(jsonId);
    return decrypted;
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
    if (record?.verification !== undefined) return record.verification;
    if (record?.captured === undefined) {
      return Promise.reject(new ApiError({ code: 'api.completion_not_found' }));
    }
    record.verification = this.verifyCapturedResponse(record.captured).then(
      (result) => {
        record.captured = undefined;
        return result;
      },
      (cause: unknown) => {
        // Keep the captured bytes so a later call can retry a transient lookup.
        if (
          isApiError(cause) &&
          (cause.retryable ||
            cause.failure.code === 'api.completion_signature_unavailable')
        ) {
          record.verification = undefined;
        } else {
          record.captured = undefined;
        }
        throw cause;
      },
    );
    return record.verification;
  }

  /** Clear captured response verification records. */
  clearResponseCache(): void {
    this.responseCacheGeneration++;
    for (const record of this.responseRecords.values()) {
      clearTimeout(record.expiry);
    }
    this.responseRecords.clear();
  }

  /** All supported endpoints share byte retention, expiry, and verification retries. */
  protected registerResponse(
    captured: VerifyCapturedResponseParams<VerificationResult>,
    generation: number,
  ): void {
    if (generation !== this.responseCacheGeneration) return;
    if (this.responseCacheTimeToLiveMs === 0) return;
    const id = captured.id;
    if (this.getResponseRecord(id) !== undefined) {
      throw new ApiError({ code: 'api.duplicate_completion_id' });
    }
    const record: ResponseRecord<VerificationResult> = { captured };
    this.responseRecords.set(id, record);
    const expire = (): void => {
      if (this.responseRecords.get(id) !== record) return;
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
        record.expiry = setTimeout(release, Math.min(remaining, 2 ** 31 - 1));
        record.expiry.unref?.();
      };
      release();
    };
    void captured.responseBody.then(expire, expire);
  }

  private getResponseRecord(
    id: string,
  ): ResponseRecord<VerificationResult> | undefined {
    const record = this.responseRecords.get(id);
    if (record?.expiresAt !== undefined && record.expiresAt <= Date.now()) {
      clearTimeout(record.expiry);
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
    let decryptResponse =
      'decryptResponse' in prepared ? prepared.decryptResponse : undefined;

    const requestBody = captureRequestEntityBody(prepared.request);
    let response = await this.sendCompletionRequest({
      request: prepared.request,
      transport: session.transport,
    });
    let wire: Uint8Array[] | undefined;
    if (decryptResponse && response.ok && isServerSentEventResponse(response)) {
      const chunks: Uint8Array[] = [];
      const body = response.body?.pipeThrough(
        new TransformStream<Uint8Array, Uint8Array>({
          transform(chunk, controller) {
            chunks.push(chunk.slice());
            controller.enqueue(chunk);
          },
        }),
      );
      response = await decryptResponse(new Response(body, response));
      wire = chunks;
      decryptResponse = undefined;
    }
    const capturedResponse = captureResponseEntityBody(
      response,
      parsed.protocol,
      wire,
    );
    return {
      response: capturedResponse.response,
      protocol: parsed.protocol,
      session,
      requestBody,
      responseBody: capturedResponse.responseBody,
      ...(decryptResponse === undefined
        ? {}
        : { decryptJsonResponse: decryptResponse }),
    };
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
        !((responses || messages) && this.supportsGatewayEndpoints))
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
        expected: 'field-level E2EE disabled for Responses and Messages',
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
  private readonly anthropic: Anthropic;

  /** Create a Response, then verify its top-level ID with verifyResponse(). */
  get responses(): InferenceResponses {
    return this.openai.responses;
  }

  /** Create a Message; verify its ID after consuming the response or stream. */
  get messages(): InferenceMessages {
    return this.anthropic.messages;
  }

  /** Send a decision request; pass result.decisionId to verifyResponse(). */
  readonly systemone: InferenceSystemOne = {
    create: async (request, options) => {
      const generation = this.responseCacheGeneration;
      return createSystemOne({
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
        registerResponse: (record) => this.registerResponse(record, generation),
      });
    },
  };

  protected constructor(options: NodeInferenceClientOptions) {
    super(options);
    this.gatewayOptions = options;
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
  }

  protected override sendSystemOneRequest(request: Request): Promise<Response> {
    const generation = this.responseCacheGeneration;
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
      registerResponse: (record) => this.registerResponse(record, generation),
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
    // Authenticate the Gateway before sending configured credentials to it.
    const gatewayAttestation = await verifyGatewayAttestation({
      attestation: gateway.attestation,
      clientBinding: gateway.clientBinding,
      policy: this.gatewayOptions.gatewayVerification?.policy,
      verifiers: this.gatewayOptions.gatewayVerification?.verifiers,
    });
    if (gatewayAttestation.signer.signingAlgo !== this.signingAlgo) {
      throw new VerificationError({ code: 'signature.signer_mismatch' });
    }
    const ohttpKeyConfig = this.getOhttpKeyConfig(
      gateway.attestation.ohttpAttestation,
      gatewayAttestation.signer,
    );
    // Pin subsequent requests to the verified report's observed TLS peer.
    const gatewayFetch = this.createGatewayFetch(
      gateway.clientBinding.spkiFingerprint,
    );
    // Parse required OHTTP configuration before authenticated evidence requests.
    const completionFetch = this.createCompletionFetch(
      gatewayFetch,
      ohttpKeyConfig,
    );
    const controller = new AbortController();
    const { signal } = controller;
    const client = new CloudApiClient({
      ...this.gatewayOptions,
      // Evidence requests share the transport and cancellation owned by preflight.
      fetch: (input, init) => {
        signal.throwIfAborted();
        return gatewayFetch(new Request(input, { ...init, signal }));
      },
    });
    const transport: GatewaySessionTransport = {
      fetch: gatewayFetch,
      fetchModelMetadata: (model) => client.fetchModelMetadata(model),
      fetchModelAttestations: (params) => client.fetchModelAttestations(params),
      fetchCompletionSignature: (params) =>
        client.fetchCompletionSignature(params),
    };
    const modelAttestations = await this.verifyModelAttestations({
      model,
      transport,
      signal,
    }).catch((cause: unknown) => {
      // Cancel outstanding evidence I/O before a retry can start a new preflight.
      // Keep the original failure instead of replacing it with an abort error.
      controller.abort(cause);
      throw cause;
    });
    const selectedModelAttestation = modelAttestations.find(
      (attestation) =>
        attestation.signer.signingAlgo === this.signingAlgo &&
        attestation.signingPublicKey !== undefined,
    );
    if (
      modelAttestations.length > 0 &&
      selectedModelAttestation === undefined
    ) {
      throw new VerificationError({ code: 'e2ee.model_public_key_required' });
    }
    const modelKey =
      selectedModelAttestation?.signingPublicKey !== undefined
        ? {
            signingAlgo: this.signingAlgo,
            publicKey: selectedModelAttestation.signingPublicKey,
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
        fetch: completionFetch,
      },
      verifyResponse: ({ id, requestBody, responseBody, signature }) => {
        if (signature.kind === 'provider_tee') {
          if (selectedModelAttestation === undefined) {
            throw new VerificationError({
              code: 'signature.kind_mismatch',
              details: { expected: 'gateway', actual: signature.kind },
            });
          }
          verifyModelResponse({
            requestBody,
            responseBody,
            signature,
            attestation: selectedModelAttestation,
          });
          const matchingAttestations = findModelAttestationsForSignature({
            attestations: modelAttestations,
            signature,
          });
          return {
            id,
            completionId: id,
            signatureKind: 'provider_tee',
            signature,
            attestations: matchingAttestations,
            attestation: selectedModelAttestation,
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
  private async verifyModelAttestations({
    model,
    transport,
    signal,
  }: VerifyModelAttestationsParams): Promise<VerifiedModelAttestation[]> {
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

    const fetchedModelAttestations = await transport.fetchModelAttestations({
      model,
      signingAlgo: this.signingAlgo,
    });
    signal.throwIfAborted();
    if (fetchedModelAttestations.attestations.length === 0) {
      throw new VerificationError({
        code: 'policy.model_attestation_required',
      });
    }
    const modelVerifiers = this.getModelVerifiers(model);
    const attestations = await Promise.all(
      fetchedModelAttestations.attestations.map((attestation) =>
        verifyModelAttestation({
          attestation,
          clientBinding: fetchedModelAttestations.clientBinding,
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

  constructor(options: InferenceClientOptions = {}) {
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
  const decoder = new TextDecoder('utf-8', { fatal: !streaming });
  let pending = '';
  let registered = false;
  const body = response.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        if (!registered) {
          pending += decoder.decode(chunk, { stream: true });
          if (streaming) {
            // The optional LF after a blank CR cannot change the event or its ID.
            const complete = takeCompleteSseRecords(pending, true);
            pending = complete.pending;
            for (const record of complete.records) {
              if (
                protocol !== 'messages' &&
                getSseRecordData(record.value) === '[DONE]'
              ) {
                throw invalidCompletionId();
              }
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
  wire?: Uint8Array[],
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
  const chunks = wire ?? [];
  let settled = false;
  const resolve = (): void => {
    if (settled) return;
    try {
      const body = concatChunks(chunks);
      if (response.ok && isServerSentEventResponse(response)) {
        if (protocol === 'messages') validateMessageStream(body);
        else validateOpenAiStream(body, protocol);
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

  let output: ReadableStreamDefaultController<Uint8Array> | undefined;
  let reading = false;
  const read = async (): Promise<void> => {
    if (reading) return;
    reading = true;
    try {
      do {
        const next = await reader.read();
        if (next.done) {
          resolve();
          output?.close();
          return;
        }
        if (!wire) chunks.push(next.value.slice());
        output?.enqueue(next.value);
      } while (output === undefined && !settled);
    } catch (cause) {
      reject(cause);
      output?.error(cause);
    } finally {
      reading = false;
    }
  };

  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      output = controller;
    },
    pull: read,
    async cancel(reason) {
      output = undefined;
      if (
        hasSseCompletionSentinel({
          chunks,
          contentType: response.headers.get('content-type'),
          protocol,
        })
      ) {
        void read();
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
  const data = getSseRecordData(text);
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
  return parseCompletionId(value);
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
    const body = concatChunks(chunks);
    if (protocol === 'messages') {
      validateMessageStream(body);
      return true;
    }
    return takeCompleteSseRecords(
      new TextDecoder().decode(body),
      true,
    ).records.some(({ value }) => getSseRecordData(value) === '[DONE]');
  } catch {
    return false;
  }
}

function validateOpenAiStream(
  body: Uint8Array,
  protocol: 'chat' | 'responses',
): void {
  // SSE delimiters are ASCII. A single-byte view keeps offsets into the signed body.
  const framing = new TextDecoder('latin1').decode(body);
  const { records, pending } = takeCompleteSseRecords(framing, true);
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let offset = 0;
  let id: string | undefined;
  for (const { value, separator } of [
    ...records,
    { value: pending, separator: '' },
  ]) {
    const end = offset + value.length + separator.length;
    let record: string;
    try {
      record = decoder.decode(body.subarray(offset, end), {
        stream: separator !== '',
      });
    } catch (cause) {
      throw invalidCompletionId(cause);
    }
    offset = end;
    const data = getSseRecordData(record);
    if (getSseEvent(record) === 'error') throw invalidCompletionId();
    if (data === '[DONE]') break;
    if (data === '') continue;
    let event: unknown;
    try {
      event = JSON.parse(data);
    } catch (cause) {
      throw invalidCompletionId(cause);
    }
    if (
      event === null ||
      typeof event !== 'object' ||
      Array.isArray(event) ||
      'error' in event ||
      ('type' in event && event.type === 'error')
    )
      throw invalidCompletionId();
    // Responses nests the receipt ID. Top-level output item IDs are unrelated.
    if (protocol === 'responses') {
      if (!('response' in event)) continue;
      event = event.response;
    } else if (!('id' in event)) {
      continue;
    }
    const candidate = parseCompletionId(event);
    if (id !== undefined && id !== candidate) throw invalidCompletionId();
    id = candidate;
  }
  if (id === undefined) throw invalidCompletionId();
}

/** EOF or a tool block alone cannot complete a signed Messages stream. */
function validateMessageStream(body: Uint8Array): void {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(body);
  } catch (cause) {
    throw invalidCompletionId(cause);
  }
  const { records, pending } = takeCompleteSseRecords(text, true);
  let id: string | undefined;
  let stopped = false;
  if (pending !== '') throw invalidCompletionId();
  for (const record of records) {
    const eventName = getSseEvent(record.value);
    if (eventName === 'error') throw invalidCompletionId();
    const data = getSseRecordData(record.value);
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
  if (id === undefined || !stopped) throw invalidCompletionId();
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
