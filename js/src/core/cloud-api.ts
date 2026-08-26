import {
  GatewayAttestation,
  NearAiCloudAttestationReport,
  VpcInfo,
} from '../types/attestation-gateway';
import { NearModelAttestation } from '../types/attestation-model';
import {
  JsonObject,
  JsonValue,
  SigningAlgo,
  TcbInfo,
} from '../types/attestation-common';
import {
  KnownChatSignature,
  SignatureLookup,
  SignatureUnavailable,
  UnknownChatSignature,
} from '../types/chat';
import { requireByteLength } from '../utils/common';
import { ApiError, VerificationError } from '../utils/errors';

type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

/** Set this on completion requests to reject model aliases before dispatch. */
export const NO_ALIASING_HEADER = 'x-no-aliasing';

export type NearAiCloudClientOptions = {
  /** API base including its version, for example https://cloud-api.near.ai/v1. */
  baseUrl: string;
  apiKey: string;
  /**
   * Injectable transport for tests. A plain fetch implementation cannot prove
   * that a later gateway response reused the report's TLS connection.
   */
  fetch?: FetchLike;
};

type FetchAttestationInput = {
  nonce: string;
  signingAlgo: SigningAlgo;
  signingAddress?: string;
};

export type FetchNearModelAttestationInput = FetchAttestationInput & {
  model: string;
};

export type FetchGatewayAttestationInput = FetchAttestationInput;

export type FetchCompletionSignatureInput = {
  chatId: string;
  signingAlgo: SigningAlgo;
};

/**
 * A narrow Cloud API client for attestation evidence and response signatures.
 * Its model methods request `provider=near`; that selects evidence only and
 * does not pin a later inference request to the NEAR fleet.
 */
export class NearAiCloudClient {
  private readonly fetchImpl: FetchLike;
  private readonly options: NearAiCloudClientOptions;

  constructor(options: NearAiCloudClientOptions) {
    this.options = {
      ...options,
      baseUrl: validateBaseUrl(options.baseUrl),
      apiKey: validateApiKey(options.apiKey),
    };
    this.fetchImpl = options.fetch ?? fetch;
  }

  /**
   * Fetch the gateway and NEAR model evidence returned by one provider-filtered
   * report request. Model aliases are rejected before the request is served.
   */
  async fetchNearAiCloudAttestationReport(
    input: FetchNearModelAttestationInput,
  ): Promise<NearAiCloudAttestationReport> {
    validateNearModelAttestationRequest(input);
    const url = this.endpoint('attestation/report');
    setAttestationQuery(url, input);
    url.searchParams.set('model', input.model);
    url.searchParams.set('provider', 'near');

    return parseNearAiCloudAttestationReport(
      await this.getJson(url, 'attestation report', {
        [NO_ALIASING_HEADER]: 'true',
      }),
    );
  }

  /** Fetch the one NEAR model report selected by a provider-filtered query. */
  async fetchNearModelAttestation(
    input: FetchNearModelAttestationInput,
  ): Promise<NearModelAttestation> {
    const report = await this.fetchNearAiCloudAttestationReport(input);
    const attestations = report.model_attestations ?? [];
    if (attestations.length !== 1) {
      throw new ApiError({
        phase: 'api',
        code: 'api.unexpected_model_attestation_count',
        details: { expectedCount: 1, actualCount: attestations.length },
      });
    }
    return attestations[0];
  }

  /** Fetch gateway evidence without selecting a model provider. */
  async fetchGatewayAttestation(
    input: FetchGatewayAttestationInput,
  ): Promise<GatewayAttestation> {
    validateAttestationRequest(input);
    const url = this.endpoint('attestation/report');
    setAttestationQuery(url, input);
    const record = requireObject(
      await this.getJson(url, 'gateway attestation report'),
      'gateway attestation report',
    );
    return parseGatewayAttestation(record.gateway_attestation);
  }

  /**
   * Fetch a response signature. An unavailable or historical signature is
   * represented explicitly rather than coerced into a successful signature.
   */
  async fetchCompletionSignature(
    input: FetchCompletionSignatureInput,
  ): Promise<SignatureLookup> {
    requireNonEmptyString(input.chatId, 'chatId');
    validateSigningAlgo(input.signingAlgo);
    const url = this.endpoint(`signature/${encodeURIComponent(input.chatId)}`);
    url.searchParams.set('signing_algo', input.signingAlgo);
    return parseSignatureLookup(
      await this.getJson(url, 'completion signature'),
    );
  }

  private endpoint(path: string): URL {
    return new URL(path, this.options.baseUrl);
  }

  private async getJson(
    url: URL,
    label: string,
    extraHeaders: HeadersInit = {},
  ): Promise<unknown> {
    let response: Response;
    try {
      const headers = new Headers(extraHeaders);
      headers.set('authorization', `Bearer ${this.options.apiKey}`);
      response = await this.fetchImpl(url, {
        headers,
      });
    } catch (cause) {
      throw new ApiError(
        {
          phase: 'api',
          code: 'api.transport_failed',
          details: { operation: label, reason: 'request' },
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
          details: { operation: label, reason: 'response_body' },
          retryable: true,
        },
        { cause },
      );
    }
    if (!response.ok) {
      throw new ApiError({
        phase: 'api',
        code: 'api.http_status',
        details: { operation: label, status: response.status },
        retryable: isRetryableHttpStatus(response.status),
      });
    }
    try {
      return JSON.parse(body);
    } catch (cause) {
      throw new ApiError(
        {
          phase: 'api',
          code: 'api.invalid_json',
          details: { operation: label },
        },
        { cause },
      );
    }
  }
}

function validateNearModelAttestationRequest(
  input: FetchNearModelAttestationInput,
): void {
  requireNonEmptyString(input.model, 'model');
  validateAttestationRequest(input);
}

function validateAttestationRequest(input: FetchAttestationInput): void {
  validateSigningAlgo(input.signingAlgo);
  requireByteLength(input.nonce, 32, 'nonce');
  if (input.signingAddress !== undefined) {
    requireByteLength(
      input.signingAddress,
      input.signingAlgo === 'ecdsa' ? 20 : 32,
      'signingAddress',
    );
  }
}

function validateBaseUrl(baseUrl: unknown): string {
  if (typeof baseUrl !== 'string') {
    throw invalidInput('baseUrl', 'invalid_url', {
      expected: 'absolute HTTP(S) URL',
    });
  }

  try {
    const parsed = new URL(baseUrl);
    if (
      (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') ||
      parsed.search ||
      parsed.hash
    ) {
      throw new TypeError('invalid base URL');
    }
  } catch {
    throw invalidInput('baseUrl', 'invalid_url', {
      expected: 'absolute HTTP(S) URL without a query or fragment',
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
    throw invalidInput(
      'apiKey',
      typeof apiKey === 'string' && apiKey.length === 0
        ? 'missing'
        : 'invalid_header',
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

function validateSigningAlgo(value: unknown): asserts value is SigningAlgo {
  if (value !== 'ecdsa' && value !== 'ed25519') {
    throw invalidInput('signingAlgo', 'unsupported_value', {
      expected: "'ecdsa' or 'ed25519'",
    });
  }
}

function requireNonEmptyString(
  value: unknown,
  field: string,
): asserts value is string {
  if (typeof value === 'string' && value.length > 0) {
    return;
  }
  throw invalidInput(
    field,
    typeof value === 'string' ? 'missing' : 'unsupported_value',
    { expected: 'non-empty string' },
  );
}

function invalidInput(
  field: string,
  reason: 'missing' | 'invalid_url' | 'invalid_header' | 'unsupported_value',
  details: { expected?: string } = {},
): VerificationError {
  return new VerificationError({
    phase: 'input',
    code: 'input.invalid',
    details: { field, reason, ...details },
  });
}

function isRetryableHttpStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

function setAttestationQuery(url: URL, input: FetchAttestationInput): void {
  url.searchParams.set('nonce', input.nonce);
  url.searchParams.set('signing_algo', input.signingAlgo);
  url.searchParams.set('include_tls_fingerprint', 'true');
  if (input.signingAddress) {
    url.searchParams.set('signing_address', input.signingAddress);
  }
}

function parseNearAiCloudAttestationReport(
  value: unknown,
): NearAiCloudAttestationReport {
  const record = requireObject(value, 'attestation report');
  const gateway = parseGatewayAttestation(record.gateway_attestation);
  const rawModelAttestations = record.model_attestations;
  let modelAttestations: NearModelAttestation[] | undefined;
  if (rawModelAttestations !== undefined) {
    if (!Array.isArray(rawModelAttestations)) {
      throw invalidResponse(
        'model_attestations',
        'array',
        rawModelAttestations,
      );
    }
    modelAttestations = rawModelAttestations.map((item, index) =>
      parseNearModelAttestation(item, `model_attestations[${index}]`),
    );
  }
  const tlsCertificate = optionalString(
    record.tls_certificate,
    'tls_certificate',
  );
  const ohttpKeyConfig = optionalString(
    record.ohttp_key_config,
    'ohttp_key_config',
  );

  return {
    gateway_attestation: gateway,
    ...(modelAttestations !== undefined
      ? { model_attestations: modelAttestations }
      : {}),
    ...(tlsCertificate !== undefined
      ? { tls_certificate: tlsCertificate }
      : {}),
    ...(ohttpKeyConfig !== undefined
      ? { ohttp_key_config: ohttpKeyConfig }
      : {}),
    ...(record.ohttp_attestation !== undefined
      ? { ohttp_attestation: record.ohttp_attestation }
      : {}),
  };
}

function parseGatewayAttestation(value: unknown): GatewayAttestation {
  const base = parseDstackAttestation(value, 'gateway_attestation');
  const record = requireObject(value, 'gateway_attestation');
  const reportData = requireString(
    record.report_data,
    'gateway_attestation.report_data',
  );
  const vpc = parseVpcInfo(record.vpc);
  return {
    ...base,
    report_data: reportData,
    ...(vpc ? { vpc } : {}),
  };
}

function parseNearModelAttestation(
  value: unknown,
  label: string,
): NearModelAttestation {
  const base = parseDstackAttestation(value, label);
  const record = requireObject(value, label);
  const nvidiaPayload = optionalStringOrNull(
    record.nvidia_payload,
    `${label}.nvidia_payload`,
  );
  return {
    ...base,
    ...(nvidiaPayload !== undefined ? { nvidia_payload: nvidiaPayload } : {}),
  };
}

function parseDstackAttestation(
  value: unknown,
  label: string,
): Omit<NearModelAttestation, 'nvidia_payload'> {
  const record = requireObject(value, label);
  const info = requireObject(record.info, `${label}.info`);
  const tcbInfo = parseTcbInfo(info.tcb_info, `${label}.info.tcb_info`);
  const signingAlgo = parseSigningAlgo(
    record.signing_algo,
    `${label}.signing_algo`,
  );
  const eventLog = requireJsonValue(record.event_log, `${label}.event_log`);
  if (typeof eventLog !== 'string' && !Array.isArray(eventLog)) {
    throw invalidResponse(
      `${label}.event_log`,
      'JSON string or array',
      eventLog,
    );
  }

  const tlsFingerprint = optionalStringOrNull(
    record.tls_cert_fingerprint,
    `${label}.tls_cert_fingerprint`,
  );
  const signingPublicKey = optionalStringOrNull(
    record.signing_public_key,
    `${label}.signing_public_key`,
  );
  const reportData = optionalString(record.report_data, `${label}.report_data`);

  return {
    request_nonce: requireString(
      record.request_nonce,
      `${label}.request_nonce`,
    ),
    signing_algo: signingAlgo,
    signing_address: requireString(
      record.signing_address,
      `${label}.signing_address`,
    ),
    intel_quote: requireString(record.intel_quote, `${label}.intel_quote`),
    event_log: eventLog,
    info: { tcb_info: tcbInfo },
    ...(tlsFingerprint !== undefined
      ? { tls_cert_fingerprint: tlsFingerprint }
      : {}),
    ...(signingPublicKey !== undefined
      ? { signing_public_key: signingPublicKey }
      : {}),
    ...(reportData !== undefined ? { report_data: reportData } : {}),
  };
}

function parseSignatureLookup(value: unknown): SignatureLookup {
  const record = requireObject(value, 'signature response');
  if (
    typeof record.error_code === 'string' &&
    typeof record.message === 'string'
  ) {
    const unavailable: SignatureUnavailable = {
      error_code: record.error_code,
      message: record.message,
    };
    return { status: 'unavailable', unavailable };
  }

  const base = {
    text: requireString(record.text, 'signature.text'),
    signature: requireString(record.signature, 'signature.signature'),
    signing_address: requireString(
      record.signing_address,
      'signature.signing_address',
    ),
    signing_algo: parseSigningAlgo(
      record.signing_algo,
      'signature.signing_algo',
    ),
  };
  if (
    record.signature_kind === 'provider_tee' ||
    record.signature_kind === 'gateway'
  ) {
    const signature: KnownChatSignature = {
      ...base,
      signature_kind: record.signature_kind,
    } as KnownChatSignature;
    return { status: 'found', signature };
  }

  const signature: UnknownChatSignature = {
    ...base,
    ...(typeof record.signature_kind === 'string'
      ? { signature_kind: record.signature_kind }
      : {}),
  };
  return { status: 'unknown_kind', signature };
}

function parseTcbInfo(value: unknown, label: string): string | TcbInfo {
  if (typeof value === 'string') {
    return value;
  }
  const record = requireObject(value, label);
  if (typeof record.app_compose !== 'string') {
    throw invalidResponse(`${label}.app_compose`, 'string', record.app_compose);
  }
  return record as TcbInfo;
}

function parseVpcInfo(value: unknown): VpcInfo | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  const record = requireObject(value, 'gateway_attestation.vpc');
  const appId = optionalString(
    record.vpc_server_app_id,
    'gateway_attestation.vpc.vpc_server_app_id',
  );
  const hostname = optionalString(
    record.vpc_hostname,
    'gateway_attestation.vpc.vpc_hostname',
  );
  return {
    ...(appId ? { vpc_server_app_id: appId } : {}),
    ...(hostname ? { vpc_hostname: hostname } : {}),
  };
}

function parseSigningAlgo(value: unknown, label: string): SigningAlgo {
  if (value === 'ecdsa' || value === 'ed25519') {
    return value;
  }
  throw invalidResponse(label, "'ecdsa' or 'ed25519'", value);
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

function requireJsonValue(value: unknown, label: string): JsonValue {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) =>
      requireJsonValue(item, `${label}[${index}]`),
    );
  }
  if (value && typeof value === 'object') {
    const result: JsonObject = {};
    for (const [key, item] of Object.entries(value)) {
      result[key] = requireJsonValue(item, `${label}.${key}`);
    }
    return result;
  }
  throw invalidResponse(label, 'JSON value', value);
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
