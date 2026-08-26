import type { GatewayAttestation } from '../types/attestation-gateway';
import type { ModelAttestation } from '../types/attestation-model';
import type {
  AttestationEventLog,
  AttestationEvidence,
  SigningAlgorithm,
  SigningIdentity,
} from '../types/attestation-common';
import type {
  CompletionSignature,
  CompletionSignatureLookup,
  SignatureUnavailable,
} from '../types/chat';
import { normalizeHex, requireByteLength } from '../utils/common';
import { ApiError, type ApiFailure, VerificationError } from '../utils/errors';
import {
  inputError,
  rejectUnknownInputKeys,
  requireInputFunction,
  requireInputObject,
} from '../utils/input';

/** Fetch implementation used for Cloud API signature and evidence requests. */
export type NearAiCloudFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

/** Set this on completion requests to reject model aliases before dispatch. */
export const NO_ALIASING_HEADER = 'x-no-aliasing';

/** Default production endpoint used when a client does not select another one. */
export const DEFAULT_NEAR_AI_CLOUD_BASE_URL = 'https://cloud-api.near.ai/v1';

export type NearAiCloudClientOptions = {
  /** Cloud API base including its version. Defaults to the production endpoint. */
  baseUrl?: string;
  /** Used only for authorized Cloud API evidence and signature requests. */
  apiKey: string;
  /** Injectable transport, including a connection-owning gateway transport. */
  fetch?: NearAiCloudFetch;
};

/** Fetch model evidence for the signer recorded in a completion signature. */
export type FetchModelAttestationInput = {
  /** Canonical model ID from the exact completion request. */
  model: string;
  /** Fresh caller-generated nonce; retain it for attestation verification. */
  nonce: string;
  /** Completion signature whose signer selects the model evidence. */
  signature: CompletionSignature;
};

/** Fetch gateway evidence for the signer recorded in a completion signature. */
export type FetchGatewayAttestationInput = {
  /** Fresh caller-generated nonce; retain it for attestation verification. */
  nonce: string;
  /** Completion signature whose signer selects the gateway evidence. */
  signature: CompletionSignature;
};

export type FetchCompletionSignatureInput = {
  /** Completion ID returned by the completion endpoint. */
  completionId: string;
  /** Defaults to `ecdsa`; choose `ed25519` only when the completion uses it. */
  algorithm?: SigningAlgorithm;
};

type ApiResource = Extract<
  ApiFailure,
  { code: 'api.transport_failed' }
>['details']['resource'];
type AttestationResource = Exclude<ApiResource, 'completion_signature'>;

/**
 * A narrow NEAR AI Cloud client for attestation evidence and response
 * signatures. It does not send completion requests or retain completion bytes.
 */
export class NearAiCloudClient {
  private readonly fetchImpl: NearAiCloudFetch;
  private readonly options: {
    baseUrl: string;
    apiKey: string;
  };

  constructor(options: NearAiCloudClientOptions) {
    const parsed = parseClientOptions(options);
    this.options = { baseUrl: parsed.baseUrl, apiKey: parsed.apiKey };
    this.fetchImpl = parsed.fetch;
  }

  /**
   * Fetch the one NEAR model report selected by the model-serving signature.
   * The client rejects model aliases before the request is dispatched.
   */
  async fetchModelAttestation(
    input: FetchModelAttestationInput,
  ): Promise<ModelAttestation> {
    const request = parseModelAttestationRequest(input);
    const url = this.endpoint('attestation/report');
    setAttestationQuery(url, request.nonce, request.signature.signer, false);
    url.searchParams.set('model', request.model);
    url.searchParams.set('provider', 'near');

    const attestation = parseSingleModelAttestation(
      await this.getJson(url, 'model_attestation', {
        [NO_ALIASING_HEADER]: 'true',
      }),
    );
    requireMatchingAttestationSigner(
      attestation,
      request.signature,
      'model_attestation',
    );
    return attestation;
  }

  /**
   * Fetch gateway evidence with the TLS fingerprint required for gateway
   * verification. The caller must still observe that fingerprint on the same
   * TLS connection it controls.
   */
  async fetchGatewayAttestation(
    input: FetchGatewayAttestationInput,
  ): Promise<GatewayAttestation> {
    const request = parseGatewayAttestationRequest(input);
    const url = this.endpoint('attestation/report');
    setAttestationQuery(url, request.nonce, request.signature.signer, true);
    const record = requireObject(
      await this.getJson(url, 'gateway_attestation'),
      'gateway attestation report',
    );
    const attestation = parseGatewayAttestation(record.gateway_attestation);
    requireMatchingAttestationSigner(
      attestation,
      request.signature,
      'gateway_attestation',
    );
    return attestation;
  }

  /**
   * Look up one completion signature without polling. Use this when an
   * application needs to handle an unavailable signature itself.
   */
  async lookupCompletionSignature(
    input: FetchCompletionSignatureInput,
  ): Promise<CompletionSignatureLookup> {
    const request = parseCompletionSignatureRequest(input);
    const url = this.endpoint(
      `signature/${encodeURIComponent(request.completionId)}`,
    );
    if (request.algorithm !== undefined) {
      url.searchParams.set('signing_algo', request.algorithm);
    }
    return parseCompletionSignatureLookup(
      await this.getJson(url, 'completion_signature'),
    );
  }

  /** Fetch one completion signature or throw when it is unavailable. */
  async fetchCompletionSignature(
    input: FetchCompletionSignatureInput,
  ): Promise<CompletionSignature> {
    const lookup = await this.lookupCompletionSignature(input);
    if (lookup.status === 'found') {
      return lookup.signature;
    }
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.unavailable',
      details: { providerErrorCode: lookup.unavailable.errorCode },
    });
  }

  private endpoint(path: string): URL {
    return new URL(path, this.options.baseUrl);
  }

  private async getJson(
    url: URL,
    resource: ApiResource,
    extraHeaders: HeadersInit = {},
  ): Promise<unknown> {
    let response: Response;
    try {
      const headers = new Headers(extraHeaders);
      headers.set('authorization', `Bearer ${this.options.apiKey}`);
      response = await this.fetchImpl(url, { headers });
    } catch (cause) {
      throw new ApiError(
        {
          phase: 'api',
          code: 'api.transport_failed',
          details: { resource, reason: 'request' },
          retryable: true,
        },
        { cause },
      );
    }

    let body: string;
    try {
      body = await response.text();
    } catch (cause) {
      throw new ApiError(
        {
          phase: 'api',
          code: 'api.transport_failed',
          details: { resource, reason: 'response_body' },
          retryable: true,
        },
        { cause },
      );
    }
    if (!response.ok) {
      throw new ApiError({
        phase: 'api',
        code: 'api.http_status',
        details: { resource, status: response.status },
        retryable: isRetryableHttpStatus(response.status, resource),
      });
    }
    try {
      return JSON.parse(body);
    } catch (cause) {
      throw new ApiError(
        {
          phase: 'api',
          code: 'api.invalid_json',
          details: { resource },
        },
        { cause },
      );
    }
  }
}

function parseClientOptions(options: unknown): {
  baseUrl: string;
  apiKey: string;
  fetch: NearAiCloudFetch;
} {
  const record = requireInputObject(options, 'options');
  rejectUnknownInputKeys(record, 'options', ['baseUrl', 'apiKey', 'fetch']);
  const suppliedFetch = record.fetch;
  return {
    baseUrl: validateBaseUrl(
      record.baseUrl === undefined
        ? DEFAULT_NEAR_AI_CLOUD_BASE_URL
        : record.baseUrl,
    ),
    apiKey: validateApiKey(record.apiKey),
    fetch:
      suppliedFetch === undefined
        ? fetch
        : (requireInputFunction(
            suppliedFetch,
            'options.fetch',
          ) as NearAiCloudFetch),
  };
}

function parseModelAttestationRequest(
  input: unknown,
): FetchModelAttestationInput {
  const record = requireInputObject(input, 'input');
  rejectUnknownInputKeys(record, 'input', ['model', 'nonce', 'signature']);
  return {
    model: requireNonEmptyString(record.model, 'model'),
    nonce: validateNonce(record.nonce),
    signature: parseSignatureSigner(record.signature, 'model_tee'),
  };
}

function parseGatewayAttestationRequest(
  input: unknown,
): FetchGatewayAttestationInput {
  const record = requireInputObject(input, 'input');
  rejectUnknownInputKeys(record, 'input', ['nonce', 'signature']);
  return {
    nonce: validateNonce(record.nonce),
    signature: parseSignatureSigner(record.signature, 'gateway'),
  };
}

function parseCompletionSignatureRequest(
  input: unknown,
): FetchCompletionSignatureInput {
  const record = requireInputObject(input, 'input');
  rejectUnknownInputKeys(record, 'input', ['completionId', 'algorithm']);
  const algorithm = record.algorithm;
  if (algorithm !== undefined) {
    validateSigningAlgorithm(algorithm);
  }
  return {
    completionId: requireNonEmptyString(record.completionId, 'completionId'),
    ...(algorithm === undefined ? {} : { algorithm }),
  };
}

function parseSignatureSigner(
  value: unknown,
  expectedSource: 'model_tee' | 'gateway',
): CompletionSignature {
  const signature = requireInputObject(value, 'signature');
  rejectUnknownInputKeys(signature, 'signature', [
    'source',
    'signedText',
    'signature',
    'signer',
  ]);
  const source = signature.source;
  if (source !== 'model_tee' && source !== 'gateway' && source !== 'unknown') {
    throw inputError('signature.source', 'unsupported_value', {
      expected: "'model_tee', 'gateway', or 'unknown'",
    });
  }
  if (source !== 'unknown' && source !== expectedSource) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.source_mismatch',
      details: { expected: expectedSource, actual: source },
    });
  }
  return {
    source,
    signedText: requireNonEmptyString(
      signature.signedText,
      'signature.signedText',
    ),
    signature: requireNonEmptyString(
      signature.signature,
      'signature.signature',
    ),
    signer: parseSigningIdentity(signature.signer),
  };
}

function parseSigningIdentity(value: unknown): SigningIdentity {
  const signer = requireInputObject(value, 'signature.signer');
  rejectUnknownInputKeys(signer, 'signature.signer', ['algorithm', 'address']);
  validateSigningAlgorithm(signer.algorithm, 'signature.signer.algorithm');
  if (typeof signer.address !== 'string') {
    throw inputError('signature.signer.address', 'unsupported_value', {
      expected: 'a hexadecimal signing address',
    });
  }
  requireByteLength(
    signer.address,
    signer.algorithm === 'ecdsa' ? 20 : 32,
    'signature.signer.address',
  );
  return { algorithm: signer.algorithm, address: signer.address };
}

function validateNonce(nonce: unknown): string {
  if (typeof nonce !== 'string') {
    throw inputError('nonce', 'unsupported_value', {
      expected: 'a 32-byte hexadecimal nonce',
    });
  }
  return requireByteLength(nonce, 32, 'nonce').toString('hex');
}

function validateBaseUrl(baseUrl: unknown): string {
  if (typeof baseUrl !== 'string') {
    throw inputError('baseUrl', 'invalid_url', {
      expected: 'absolute HTTPS URL',
    });
  }

  try {
    const parsed = new URL(baseUrl);
    if (
      parsed.protocol !== 'https:' ||
      parsed.search ||
      parsed.hash ||
      parsed.username ||
      parsed.password
    ) {
      throw new TypeError('invalid base URL');
    }
  } catch {
    throw inputError('baseUrl', 'invalid_url', {
      expected: 'absolute HTTPS URL without credentials, query, or fragment',
    });
  }

  return baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
}

function validateApiKey(apiKey: unknown): string {
  if (
    typeof apiKey !== 'string' ||
    apiKey.length === 0 ||
    containsHttpHeaderControl(apiKey)
  ) {
    throw inputError(
      'apiKey',
      apiKey === undefined
        ? 'missing'
        : typeof apiKey === 'string' && apiKey.length === 0
          ? 'missing'
          : typeof apiKey === 'string'
            ? 'invalid_header'
            : 'unsupported_value',
      { expected: 'non-empty HTTP header value' },
    );
  }
  return apiKey;
}

function containsHttpHeaderControl(value: string): boolean {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function validateSigningAlgorithm(
  value: unknown,
  field = 'algorithm',
): asserts value is SigningAlgorithm {
  if (value !== 'ecdsa' && value !== 'ed25519') {
    throw inputError(field, 'unsupported_value', {
      expected: "'ecdsa' or 'ed25519'",
    });
  }
}

function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value === 'string' && value.length > 0) {
    return value;
  }
  throw inputError(
    field,
    typeof value === 'string' ? 'missing' : 'unsupported_value',
    { expected: 'non-empty string' },
  );
}

function isRetryableHttpStatus(status: number, resource: ApiResource): boolean {
  return (
    (resource === 'completion_signature' && status === 404) ||
    status === 408 ||
    status === 425 ||
    status === 429 ||
    status >= 500
  );
}

function setAttestationQuery(
  url: URL,
  nonce: string,
  signer: SigningIdentity,
  includeTlsFingerprint: boolean,
): void {
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('signing_algo', signer.algorithm);
  url.searchParams.set('signing_address', signer.address);
  if (includeTlsFingerprint) {
    url.searchParams.set('include_tls_fingerprint', 'true');
  }
}

function parseSingleModelAttestation(value: unknown): ModelAttestation {
  const record = requireObject(value, 'model attestation report');
  const rawAttestations = record.model_attestations;
  if (!Array.isArray(rawAttestations)) {
    throw invalidResponse('model_attestations', 'array', rawAttestations);
  }
  if (rawAttestations.length !== 1) {
    throw new ApiError({
      phase: 'api',
      code: 'api.unexpected_model_attestation_count',
      details: { expectedCount: 1, actualCount: rawAttestations.length },
    });
  }
  return parseModelAttestation(rawAttestations[0], 'model_attestations[0]');
}

function parseGatewayAttestation(value: unknown): GatewayAttestation {
  const base = parseAttestationEvidence(value, 'gateway_attestation');
  const record = requireObject(value, 'gateway_attestation');
  const reportData = requireString(
    record.report_data,
    'gateway_attestation.report_data',
  );
  return { ...base, reportedQuoteData: reportData };
}

function parseModelAttestation(
  value: unknown,
  label: string,
): ModelAttestation {
  const base = parseAttestationEvidence(value, label);
  const record = requireObject(value, label);
  const nvidiaPayload = optionalStringOrNull(
    record.nvidia_payload,
    `${label}.nvidia_payload`,
  );
  return {
    ...base,
    ...(nvidiaPayload !== undefined ? { nvidiaPayload } : {}),
  };
}

function parseAttestationEvidence(
  value: unknown,
  label: string,
): AttestationEvidence {
  const record = requireObject(value, label);
  const info = requireObject(record.info, `${label}.info`);
  const appCompose = parseAppCompose(info.tcb_info, `${label}.info.tcb_info`);
  const signingAlgorithm = parseSigningAlgorithm(
    record.signing_algo,
    `${label}.signing_algo`,
  );
  const signingAddress = requireString(
    record.signing_address,
    `${label}.signing_address`,
  );
  validateApiSigningAddress(
    signingAddress,
    signingAlgorithm,
    `${label}.signing_address`,
  );
  const eventLog = parseEventLog(record.event_log, `${label}.event_log`);

  const tlsFingerprint = optionalStringOrNull(
    record.tls_cert_fingerprint,
    `${label}.tls_cert_fingerprint`,
  );
  const reportData = optionalString(record.report_data, `${label}.report_data`);

  return {
    nonce: requireString(record.request_nonce, `${label}.request_nonce`),
    signer: {
      algorithm: signingAlgorithm,
      address: signingAddress,
    },
    intelQuote: requireString(record.intel_quote, `${label}.intel_quote`),
    eventLog,
    appCompose,
    ...(tlsFingerprint !== undefined
      ? { declaredSpkiFingerprint: tlsFingerprint }
      : {}),
    ...(reportData !== undefined ? { reportedQuoteData: reportData } : {}),
  };
}

function parseCompletionSignatureLookup(
  value: unknown,
): CompletionSignatureLookup {
  const record = requireObject(value, 'signature response');
  if (
    typeof record.error_code === 'string' &&
    typeof record.message === 'string'
  ) {
    const unavailable: SignatureUnavailable = {
      errorCode: record.error_code,
      message: record.message,
    };
    return { status: 'unavailable', unavailable };
  }

  const signingAlgorithm = parseSigningAlgorithm(
    record.signing_algo,
    'signature.signing_algo',
  );
  const signingAddress = requireString(
    record.signing_address,
    'signature.signing_address',
  );
  validateApiSigningAddress(
    signingAddress,
    signingAlgorithm,
    'signature.signing_address',
  );
  const base = {
    signedText: requireString(record.text, 'signature.text'),
    signature: requireString(record.signature, 'signature.signature'),
    signer: { address: signingAddress, algorithm: signingAlgorithm },
  };
  return {
    status: 'found',
    signature: {
      ...base,
      source: parseSignatureSource(record.signature_kind),
    },
  };
}

function parseSignatureSource(value: unknown): CompletionSignature['source'] {
  if (value === undefined) {
    return 'unknown';
  }
  if (value === 'provider_tee') {
    return 'model_tee';
  }
  if (value === 'gateway') {
    return 'gateway';
  }
  throw invalidResponse(
    'signature.signature_kind',
    "'provider_tee' or 'gateway'",
    value,
  );
}

function parseAppCompose(value: unknown, label: string): string {
  let parsed = value;
  if (typeof parsed === 'string') {
    try {
      parsed = JSON.parse(parsed);
    } catch {
      throw invalidResponse(label, 'JSON object', value);
    }
  }
  const record = requireObject(parsed, label);
  return requireString(record.app_compose, `${label}.app_compose`);
}

function parseEventLog(value: unknown, label: string): AttestationEventLog {
  if (typeof value === 'string' || Array.isArray(value)) {
    return value;
  }
  throw invalidResponse(label, 'JSON string or array', value);
}

function parseSigningAlgorithm(
  value: unknown,
  label: string,
): SigningAlgorithm {
  if (value === 'ecdsa' || value === 'ed25519') {
    return value;
  }
  throw invalidResponse(label, "'ecdsa' or 'ed25519'", value);
}

function requireMatchingAttestationSigner(
  attestation: AttestationEvidence,
  signature: CompletionSignature,
  resource: AttestationResource,
): void {
  if (
    attestation.signer.algorithm !== signature.signer.algorithm ||
    normalizeHex(attestation.signer.address) !==
      normalizeHex(signature.signer.address)
  ) {
    throw new ApiError({
      phase: 'api',
      code: 'api.attestation_signer_mismatch',
      details: { resource },
    });
  }
}

function validateApiSigningAddress(
  value: string,
  algorithm: SigningAlgorithm,
  label: string,
): void {
  const normalized =
    value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  const expectedBytes = algorithm === 'ecdsa' ? 20 : 32;
  if (
    normalized.length !== expectedBytes * 2 ||
    !/^[0-9a-fA-F]+$/.test(normalized)
  ) {
    throw invalidResponse(
      label,
      `${expectedBytes}-byte hexadecimal signing address`,
      value,
    );
  }
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidResponse(label, 'object', value);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw invalidResponse(label, 'string', value);
  }
  return value;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return requireString(value, label);
}

function optionalStringOrNull(
  value: unknown,
  label: string,
): string | null | undefined {
  if (value === undefined || value === null) {
    return value as undefined | null;
  }
  return requireString(value, label);
}

function invalidResponse(
  path: string,
  expected: string,
  value: unknown,
): ApiError {
  return new ApiError({
    phase: 'api',
    code: 'api.invalid_response',
    details: { path, expected, actual: describeValue(value) },
  });
}

function describeValue(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'array';
  }
  return typeof value;
}
