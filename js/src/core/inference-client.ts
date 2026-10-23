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
import { getSseDataRecords, takeCompleteSseRecords } from '../utils/sse';
import { verifyGatewayAttestation } from './attestation-gateway';
import { verifyModelAttestation } from './attestation-model';
import {
  BoundedBodyBuffer,
  readBoundedBody,
  requireBodySize,
} from './body-limit';
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
import { measureE2eeChatRequestBytes } from './e2ee-chat';
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

type ResponseRecord<VerificationResult> =
  VerifyCapturedResponseParams<VerificationResult> & {
    verification?: Promise<VerificationResult>;
    retainedBytes?: number;
    expiry?: ReturnType<typeof setTimeout>;
  };

type ParsedSecureRequest = {
  readonly model: string;
  readonly request: Request;
};

type PreparePlaintextRequestParams = {
  readonly request: Request;
  readonly modelKey?: E2eeModelKey;
};

type SendSecureCompletionParams = {
  readonly input: RequestInfo | URL;
  readonly init?: RequestInit;
};

type SentSecureCompletion<VerificationResult> = {
  response: Response;
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
    return this.gatewayFetch(
      new Request(request, {
        signal: AbortSignal.any([this.signal, request.signal]),
      }),
    );
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
  protected readonly maxBodyBytes: number;
  private readonly maxCacheEntries: number;
  private readonly maxReceiptCacheBytes: number;
  private readonly attestationCacheTimeToLiveMs: number;
  protected readonly e2eeEnabled: boolean;
  private readonly responseCacheTimeToLiveMs: number;
  private readonly responses = new Map<
    string,
    ResponseRecord<VerificationResult>
  >();
  private readonly responseVerifications = new Map<
    Promise<VerificationResult>,
    ResponseRecord<VerificationResult>
  >();
  readonly chat: InferenceChat;
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
    this.maxBodyBytes = options.maxBodyBytes ?? 64 * 1024 * 1024;
    this.maxCacheEntries = options.maxCacheEntries ?? 128;
    this.maxReceiptCacheBytes =
      options.maxReceiptCacheBytes ?? 64 * 1024 * 1024;
    for (const [field, value] of Object.entries({
      maxBodyBytes: this.maxBodyBytes,
      maxCacheEntries: this.maxCacheEntries,
      maxReceiptCacheBytes: this.maxReceiptCacheBytes,
    })) {
      if (!Number.isSafeInteger(value) || value <= 0)
        throw invalidInput({
          field,
          reason: 'unsupported_value',
          expected: 'a positive safe integer',
        });
    }
    this.attestationCacheTimeToLiveMs =
      options.attestationCacheTimeToLiveMs ?? DEFAULT_CACHE_TIME_TO_LIVE_MS;
    this.e2eeEnabled = options.e2ee ?? false;
    this.signingAlgo = options.signingAlgo ?? 'ed25519';
    this.ohttpEnabled = options.ohttp ?? false;
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

  /** Only Chat uses OHTTP; evidence and signature fetches retain their transport. */
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
   * Send one verified Chat Completions or Jev System One request.
   *
   * Only POST requests to this client's configured inference endpoints
   * are accepted. Other API paths, including Responses, are rejected locally.
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
        register: (completionId) =>
          this.registerResponse({
            id: completionId,
            requestBody,
            responseBody,
            session: completion.session,
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
  verifyResponse(
    id: string,
    { signal }: { readonly signal?: AbortSignal } = {},
  ): Promise<VerificationResult> {
    if (signal?.aborted) return Promise.reject(signal.reason);
    const record = this.responses.get(id);
    if (record === undefined) {
      return Promise.reject(new ApiError({ code: 'api.completion_not_found' }));
    }
    if (signal === undefined && record.verification !== undefined)
      return record.verification;
    if (this.responseVerifications.size >= this.maxCacheEntries) {
      return Promise.reject(
        invalidInput({
          field: 'id',
          reason: 'unsupported_value',
          expected: 'fewer concurrent receipt verifications',
        }),
      );
    }
    const verification = this.verifyCapturedResponse(record, signal).finally(
      () => {
        this.responseVerifications.delete(verification);
      },
    );
    this.responseVerifications.set(verification, record);
    // A caller-owned deadline must not cancel another caller's cached lookup.
    if (signal !== undefined) return verification;
    record.verification = verification.catch((cause: unknown) => {
      if (
        isApiError(cause) &&
        (cause.retryable ||
          cause.failure.code === 'api.completion_signature_unavailable')
      )
        record.verification = undefined;
      throw cause;
    });
    return record.verification;
  }

  /** Both endpoints share byte retention, expiry, and verification retries. */
  protected registerResponse(params: ResponseRecord<VerificationResult>): void {
    if (this.responseCacheTimeToLiveMs === 0) return;
    const id = params.id;
    const previous = this.responses.get(id);
    if (previous?.expiry !== undefined) clearTimeout(previous.expiry);
    const record: ResponseRecord<VerificationResult> = { ...params };
    this.responses.set(id, record);
    // Streaming placeholders permit verifyResponse before EOF. Only completed
    // records consume the retained-byte/count budgets; active streams are body-bounded.
    void record.responseBody.then(
      (bytes) => {
        record.retainedBytes = record.requestBody.byteLength + bytes.byteLength;
        if (this.responses.get(id) === record) {
          // Completion order determines FIFO, regardless of stream start time.
          this.responses.delete(id);
          this.responses.set(id, record);
        }
        const completed = [...this.responses].filter(
          ([, entry]) => entry.retainedBytes !== undefined,
        );
        const activeRecords = new Set(this.responseVerifications.values());
        const retainedRecords = new Set([
          ...completed.map(([, entry]) => entry),
          ...activeRecords,
        ]);
        let retained = [...retainedRecords].reduce(
          (total, entry) => total + (entry.retainedBytes ?? 0),
          0,
        );
        while (
          completed.length > this.maxCacheEntries ||
          retained > this.maxReceiptCacheBytes
        ) {
          const oldest = completed.shift();
          if (oldest === undefined) break;
          if (!activeRecords.has(oldest[1])) {
            retained -= oldest[1].retainedBytes ?? 0;
          }
          if (oldest[1].expiry !== undefined) clearTimeout(oldest[1].expiry);
          this.responses.delete(oldest[0]);
        }
        if (this.responses.get(id) !== record) return;
        record.expiry = setTimeout(() => {
          if (this.responses.get(id) === record) this.responses.delete(id);
        }, this.responseCacheTimeToLiveMs);
        record.expiry.unref?.();
      },
      () => {
        if (this.responses.get(id) === record) this.responses.delete(id);
      },
    );
  }

  protected responseByteLimit(requestSize: number): number {
    requireBodySize(requestSize, this.maxBodyBytes);
    if (this.responseCacheTimeToLiveMs === 0) return this.maxBodyBytes;
    if (requestSize >= this.maxReceiptCacheBytes)
      throw new ApiError({ code: 'api.body_too_large' });
    return Math.min(this.maxBodyBytes, this.maxReceiptCacheBytes - requestSize);
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
              modelKey: session.modelKey,
            }),
          };
    const decryptResponse =
      'decryptResponse' in prepared ? prepared.decryptResponse : undefined;

    const requestBytes = await captureRequestEntityBody(prepared.request);
    const responseLimit = this.responseByteLimit(requestBytes.byteLength);
    const requestBody = Promise.resolve(requestBytes);
    const response = await this.sendCompletionRequest({
      request: prepared.request,
      transport: session.transport,
    });
    const capturedResponse = captureResponseEntityBody(
      response,
      response.ok ? responseLimit : this.maxBodyBytes,
    );
    return {
      response: capturedResponse.response,
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

  private async verifyCapturedResponse(
    {
      id,
      requestBody,
      responseBody,
      session,
    }: VerifyCapturedResponseParams<VerificationResult>,
    signal?: AbortSignal,
  ): Promise<VerificationResult> {
    const bytes = await (signal === undefined
      ? responseBody
      : awaitWithAbort({ operation: responseBody, signal }));
    signal?.throwIfAborted();
    const signature = await session.transport.fetchCompletionSignature({
      completionId: id,
      signingAlgo: this.signingAlgo,
      signal,
    });

    if (signature.signer.signingAlgo !== this.signingAlgo) {
      throw new VerificationError({ code: 'signature.signer_mismatch' });
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

    if (this.pendingVerifications.size >= this.maxCacheEntries) {
      return Promise.reject(
        invalidInput({
          field: 'model',
          reason: 'unsupported_value',
          expected: 'fewer concurrent preflights',
        }),
      );
    }
    const verification = this.createVerificationState(model);
    this.pendingVerifications.set(cacheKey, verification);
    void verification.then(
      (session) => {
        if (this.attestationCacheTimeToLiveMs !== 0) {
          this.removeExpiredVerifications(Date.now());
          while (this.cachedVerifications.size >= this.maxCacheEntries) {
            const oldest = this.cachedVerifications.keys().next().value;
            if (oldest === undefined) break;
            this.cachedVerifications.delete(oldest);
          }
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
    const original = createRequest(input, init);
    this.requireSupportedEndpoint(original);
    let bytes: Uint8Array<ArrayBuffer>;
    try {
      // Retained plaintext receipts also need space for a nonempty response.
      bytes = await readBoundedBody(
        original.body,
        this.e2eeEnabled || this.responseCacheTimeToLiveMs === 0
          ? this.maxBodyBytes
          : Math.min(this.maxBodyBytes, this.maxReceiptCacheBytes - 1),
        original.signal,
      );
    } catch (cause) {
      original.signal.throwIfAborted();
      if (isApiError(cause)) throw cause;
      throw invalidInput(
        {
          field: 'request body',
          reason: 'invalid_json',
          expected: 'a JSON Chat Completions request',
        },
        cause,
      );
    }
    const request = new Request(original, { body: bytes });
    const value = await decodeChatRequest({ request });
    const generic = v.safeParse(ChatCompletionRequestSchema, value);
    if (!generic.success) {
      throw invalidInput({
        field: 'request body',
        reason: 'unsupported_value',
        expected: 'a JSON Chat Completions request with a string model',
      });
    }
    if (this.e2eeEnabled) {
      this.responseByteLimit(
        measureE2eeChatRequestBytes(generic.output, this.signingAlgo),
      );
    }
    const model = generic.output.model;
    return { model, request };
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

  /** Send a decision request; pass result.decisionId to verifyResponse(). */
  readonly systemone: InferenceSystemOne = {
    create: async (request, options) =>
      createSystemOne({
        request,
        options,
        baseUrl: this.getBaseUrl(),
        encryptionEnabled: this.e2eeEnabled || this.ohttpEnabled,
        responseByteLimit: (size) => this.responseByteLimit(size),
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
  }

  protected override sendSystemOneRequest(request: Request): Promise<Response> {
    return sendSystemOne({
      request,
      responseByteLimit: (size) => this.responseByteLimit(size),
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
  readonly register: (id: string) => void;
};

/** Register IDs before forwarding their bytes; streaming follows consumer backpressure. */
function registerCompletionResponse({
  response,
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
                id = getSseCompletionId(record.value);
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
  limit: number,
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
  const buffer = new BoundedBodyBuffer(limit);
  const append = (chunk: Uint8Array): void => {
    buffer.append(chunk);
  };
  let settled = false;
  const resolve = (): void => {
    if (settled) return;
    try {
      const body = buffer.take();
      settled = true;
      resolveBody(body);
    } catch (cause) {
      reject(cause);
    }
  };
  const reject = (cause: unknown): void => {
    if (settled) return;
    settled = true;
    buffer.clear();
    rejectBody(cause);
    void reader.cancel(cause).catch(() => undefined);
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
        append(next.value);
        controller.enqueue(next.value);
      } catch (cause) {
        reject(cause);
        controller.error(cause);
      }
    },
    async cancel(reason) {
      if (
        hasSseCompletionSentinel({
          body: buffer.view(),
          contentType: response.headers.get('content-type'),
        })
      ) {
        void drainResponseEntityBody({ reader, append, resolve, reject });
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
  readonly body: Uint8Array;
  readonly contentType: string | null;
};

function hasSseCompletionSentinel({
  body,
  contentType,
}: HasSseCompletionSentinelParams): boolean {
  if (!isServerSentEventContentType(contentType)) {
    return false;
  }
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(body);
    return getSseDataRecords(text).some((data) => data === '[DONE]');
  } catch {
    return false;
  }
}

type DrainResponseEntityBodyParams = {
  readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  readonly append: (chunk: Uint8Array) => void;
  readonly resolve: () => void;
  readonly reject: (cause: unknown) => void;
};

async function drainResponseEntityBody({
  reader,
  append,
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
      append(next.value);
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
        path: 'Chat Completions response.id',
        expected: 'a non-empty completion ID',
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
