import OpenAI from 'openai';
import * as v from 'valibot';
import { ChatCompletionRequestSchema } from '../schemas';
import type {
  ModelAttestationVerifiers,
  VerifiedModelAttestation,
} from '../types/verification';
import type {
  ChatCompletionRequest,
  NearAiSecureClientOptions,
  SecureChat,
  SecureChatCompletionRequest,
  SecureChatCompletionResponse,
  SecureClientOptions,
  VerifiedSecureSession,
} from '../types/secure-client';
import { ApiError, VerificationError } from '../utils/errors';
import {
  AttestationClient,
  getAuthorizationToken,
  NO_ALIASING_HEADER,
  resolveCloudApiBaseUrl,
} from './cloud-api';
import { verifyGatewayAttestation } from './attestation-gateway';
import { verifyModelAttestation } from './attestation-model';
import {
  createE2eeChatSseTransform,
  decryptE2eeChatResponse,
  encryptE2eeChatRequest,
  parseE2eeChatResponse,
} from './e2ee-chat';
import { createE2eeClientKeyPair, type E2eeClientKeyPair } from './e2ee';

type SecureSessionState = {
  readonly session: VerifiedSecureSession;
  readonly modelSigningPublicKey: string;
};

type ParsedPlaintextRequest = {
  readonly e2ee: false;
  readonly request: Request;
};

type ParsedE2eeRequest = {
  readonly e2ee: true;
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

/**
 * A verified Chat Completions transport.
 *
 * Every `fetch()` call obtains and verifies fresh Gateway and model evidence
 * before dispatch. With the default `e2ee: true`, supported fields are then
 * encrypted to a quote-bound model key and integrity-checked on the way back.
 * With `e2ee: false`, the same evidence and policy checks run, but the Chat
 * request and response remain plaintext while the request stays pinned to the
 * verified model key.
 */
export class SecureClient {
  private readonly attestationClient: AttestationClient;
  private readonly authorizationToken: string;
  private readonly baseUrl: string;
  private readonly e2eeEnabled: boolean;
  private readonly model: string;
  private readonly options: SecureClientOptions;
  /** Shares only an in-progress verification; completed evidence is never cached. */
  private pendingVerification: Promise<SecureSessionState> | undefined;

  constructor(options: SecureClientOptions) {
    this.attestationClient = new AttestationClient(options);
    this.authorizationToken = getAuthorizationToken(options);
    this.baseUrl = resolveCloudApiBaseUrl(options.baseUrl);
    this.e2eeEnabled = options.e2ee !== false;
    this.model = options.model;
    this.options = options;
  }

  /** Verify fresh Gateway and model evidence without sending a Chat Completions request. */
  async verify(): Promise<VerifiedSecureSession> {
    return (await this.startVerification()).session;
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
    const parsed = await this.parseSecureRequest(input, init);
    const session = await this.verify();
    const modelSigningPublicKey = session.modelSigningPublicKey;

    if (!parsed.e2ee) {
      return this.sendCompletionRequest(
        this.preparePlaintextRequest({
          request: parsed.request,
          modelSigningPublicKey,
        }),
      );
    }

    const encrypted = this.encryptSecureRequest({
      parsed,
      modelSigningPublicKey,
    });
    const response = await this.sendCompletionRequest(encrypted.request);
    if (!response.ok) {
      return response;
    }
    return this.decryptSecureResponse({
      response,
      clientKeyPair: encrypted.clientKeyPair,
    });
  }

  private startVerification(): Promise<SecureSessionState> {
    if (this.pendingVerification === undefined) {
      const verification = this.createVerificationState();
      this.pendingVerification = verification;
      void verification.then(
        () => this.clearPendingVerification(verification),
        () => this.clearPendingVerification(verification),
      );
    }
    return this.pendingVerification;
  }

  private clearPendingVerification(
    verification: Promise<SecureSessionState>,
  ): void {
    if (this.pendingVerification === verification) {
      this.pendingVerification = undefined;
    }
  }

  private async createVerificationState(): Promise<SecureSessionState> {
    const [gateway, fetchedModels] = await Promise.all([
      this.attestationClient.fetchGatewayAttestation({
        includeSpkiFingerprint: false,
      }),
      this.attestationClient.fetchModelAttestations({
        model: this.model,
        signingAlgo: 'ed25519',
      }),
    ]);
    if (fetchedModels.attestations.length === 0) {
      throw new VerificationError({
        code: 'policy.model_attestation_required',
      });
    }

    const modelVerifiers = this.getModelVerifiers();
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
      modelSigningPublicKey,
      session: {
        model: this.model,
        gatewayAttestation,
        modelAttestations,
        modelSigningPublicKey,
        modelDeploymentProvenance: modelAttestations.every(
          (attestation) => attestation.deploymentProvenance === 'verified',
        )
          ? 'verified'
          : 'not_checked',
      },
    };
  }

  private getModelVerifiers(): ModelAttestationVerifiers | undefined {
    const verifiers = this.options.modelVerification?.verifiers;
    const deploymentPolicy = this.options.deploymentPolicy;
    if (verifiers?.deployment === undefined && deploymentPolicy === undefined) {
      return verifiers;
    }
    return {
      ...verifiers,
      deployment: async (deployment) => {
        await verifiers?.deployment?.(deployment);
        await deploymentPolicy?.({ model: this.model, deployment });
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
    this.requireConfiguredModel(generic.output);
    if (this.e2eeEnabled) {
      const body = generic.output as SecureChatCompletionRequest;
      return {
        e2ee: true,
        request,
        body,
      };
    }
    return { e2ee: false, request };
  }

  private requireConfiguredModel(body: ChatCompletionRequest): void {
    if (body.model !== this.model) {
      throw invalidInput({
        field: 'model',
        reason: 'unsupported_value',
        expected: this.model,
        actual: body.model,
      });
    }
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
    const client = new OpenAI({
      apiKey: getAuthorizationToken(options),
      baseURL: this.secure.getBaseUrl(),
      dangerouslyAllowBrowser: true,
      fetch: (input, init) => this.secure.fetch(input, init),
      maxRetries: 0,
    });
    this.chat = client.chat;
  }

  /** Verify fresh Gateway and model evidence without sending a Chat Completions request. */
  async verify(): Promise<VerifiedSecureSession> {
    return this.secure.verify();
  }
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

function isServerSentEventResponse(response: Response): boolean {
  return (
    response.headers
      .get('content-type')
      ?.toLowerCase()
      .startsWith('text/event-stream') ?? false
  );
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
