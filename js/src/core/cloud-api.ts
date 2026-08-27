import type { GatewayAttestation } from '../types/attestation-gateway';
import type { ModelAttestation } from '../types/attestation-model';
import type {
  AttestationEvidence,
  SigningAlgorithm,
  SigningIdentity,
} from '../types/attestation-common';
import type {
  CompletionSignature,
  CompletionSignatureLookup,
  SignatureUnavailable,
} from '../types/chat';
import {
  CloudApiCompletionSignatureResponseSchema,
  CloudApiAttestationInfoEnvelopeSchema,
  CloudApiGatewayAttestationResponseSchema,
  CloudApiGatewayAttestationSchema,
  CloudApiInfoSchema,
  CloudApiModelAttestationResponseSchema,
  CloudApiModelAttestationSchema,
  CloudApiTcbInfoSchema,
  CloudApiUnavailableSignatureResponseSchema,
  FetchCompletionSignatureInputSchema,
  FetchGatewayAttestationInputSchema,
  FetchModelAttestationInputSchema,
  NearAiCloudClientOptionsSchema,
  ResponseBodySchema,
  ResponseLikeSchema,
} from '../schemas';
import type {
  CloudApiGatewayAttestation,
  CloudApiInfo,
  CloudApiModelAttestation,
  FetchCompletionSignatureInput,
  FetchGatewayAttestationInput,
  FetchModelAttestationInput,
  NearAiCloudClientOptions,
  NearAiCloudFetch,
  ResponseLike,
} from '../schemas';
import { normalizeHex, requireByteLength } from '../utils/common';
import { ApiError, type ApiFailure, VerificationError } from '../utils/errors';
import { inputError } from '../utils/input';
import { parseApiResponse, parsePublicInput, tryParse } from '../utils/schema';

export type {
  FetchCompletionSignatureInput,
  FetchGatewayAttestationInput,
  FetchModelAttestationInput,
  NearAiCloudClientOptions,
  NearAiCloudFetch,
} from '../schemas';

/** Set this on completion requests to reject model aliases before dispatch. */
export const NO_ALIASING_HEADER = 'x-no-aliasing';

/** Default production endpoint used when a client does not select another one. */
export const DEFAULT_NEAR_AI_CLOUD_BASE_URL = 'https://cloud-api.near.ai/v1';

type ApiResource = Extract<
  ApiFailure,
  { code: 'api.transport_failed' }
>['details']['resource'];
type AttestationResource = 'model_attestation';

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
   * Fetch standalone gateway evidence. The caller must independently observe
   * the TLS peer fingerprint for this attestation request.
   */
  async fetchGatewayAttestation(
    input: FetchGatewayAttestationInput,
  ): Promise<GatewayAttestation> {
    const request = parseGatewayAttestationRequest(input);
    const url = this.endpoint('attestation/report');
    setGatewayAttestationQuery(url, request.nonce, request.algorithm);
    const report = parseApiResponse(
      CloudApiGatewayAttestationResponseSchema,
      await this.getJson(url, 'gateway_attestation'),
      'gateway attestation report',
    );
    return parseGatewayAttestation(report.gateway_attestation);
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
    let rawResponse: unknown;
    try {
      const headers = new Headers(extraHeaders);
      headers.set('authorization', `Bearer ${this.options.apiKey}`);
      rawResponse = await this.fetchImpl(url, { headers });
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
    const response = parseResponseLike(rawResponse, `${resource} response`);

    let rawBody: unknown;
    try {
      rawBody = await response.text();
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
    const body = parseApiResponse(
      ResponseBodySchema,
      rawBody,
      `${resource} response body`,
    );
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

type ParsedClientOptions = {
  baseUrl: string;
  apiKey: string;
  fetch: NearAiCloudFetch;
};

function parseClientOptions(options: unknown): ParsedClientOptions {
  const parsed = parsePublicInput(
    NearAiCloudClientOptionsSchema,
    options,
    'options',
  );

  return {
    baseUrl: validateBaseUrl(
      parsed.baseUrl === undefined
        ? DEFAULT_NEAR_AI_CLOUD_BASE_URL
        : parsed.baseUrl,
    ),
    apiKey: validateApiKey(parsed.apiKey),
    fetch: parsed.fetch ?? fetch,
  };
}

type ParsedModelAttestationRequest = FetchModelAttestationInput;

function parseModelAttestationRequest(
  input: unknown,
): ParsedModelAttestationRequest {
  const parsed = parsePublicInput(
    FetchModelAttestationInputSchema,
    input,
    'input',
  );

  return {
    model: requireNonEmptyString(parsed.model, 'model'),
    nonce: validateNonce(parsed.nonce),
    signature: parseSignatureSigner(parsed.signature, 'provider_tee'),
  };
}

type ParsedGatewayAttestationRequest = {
  nonce: string;
  algorithm: SigningAlgorithm;
};

function parseGatewayAttestationRequest(
  input: unknown,
): ParsedGatewayAttestationRequest {
  const parsed = parsePublicInput(
    FetchGatewayAttestationInputSchema,
    input,
    'input',
  );

  return {
    nonce: validateNonce(parsed.nonce),
    algorithm: parsed.algorithm ?? 'ed25519',
  };
}

type ParsedCompletionSignatureRequest = FetchCompletionSignatureInput;

function parseCompletionSignatureRequest(
  input: unknown,
): ParsedCompletionSignatureRequest {
  const parsed = parsePublicInput(
    FetchCompletionSignatureInputSchema,
    input,
    'input',
  );

  return {
    completionId: requireNonEmptyString(parsed.completionId, 'completionId'),
    ...(parsed.algorithm === undefined ? {} : { algorithm: parsed.algorithm }),
  };
}

function parseSignatureSigner(
  signature: CompletionSignature,
  expectedKind: CompletionSignature['kind'],
): CompletionSignature {
  const kind = signature.kind;
  if (kind !== expectedKind) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.kind_mismatch',
      details: { expected: expectedKind, actual: kind },
    });
  }
  return {
    kind,
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

function parseSigningIdentity(signer: SigningIdentity): SigningIdentity {
  requireByteLength(
    signer.address,
    signer.algorithm === 'ecdsa' ? 20 : 32,
    'signature.signer.address',
  );
  return { algorithm: signer.algorithm, address: signer.address };
}

function validateNonce(nonce: string): string {
  return requireByteLength(nonce, 32, 'nonce').toString('hex');
}

function validateBaseUrl(baseUrl: string): string {
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

function validateApiKey(apiKey: string): string {
  if (apiKey.length === 0 || containsHttpHeaderControl(apiKey)) {
    throw inputError(
      'apiKey',
      apiKey.length === 0 ? 'missing' : 'invalid_header',
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

function requireNonEmptyString(value: string, field: string): string {
  if (value.length > 0) {
    return value;
  }
  throw inputError(field, 'missing', { expected: 'non-empty string' });
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

function parseResponseLike(value: unknown, root: string): ResponseLike {
  const parsed = parseApiResponse(ResponseLikeSchema, value, root);
  return {
    ok: parsed.ok,
    status: parsed.status,
    text: () => parsed.text.call(value),
  };
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

function setGatewayAttestationQuery(
  url: URL,
  nonce: string,
  algorithm: SigningAlgorithm,
): void {
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('signing_algo', algorithm);
  url.searchParams.set('include_tls_fingerprint', 'true');
}

function parseSingleModelAttestation(value: unknown): ModelAttestation {
  const report = parseApiResponse(
    CloudApiModelAttestationResponseSchema,
    value,
    'model attestation report',
  );
  const rawAttestations = report.model_attestations;
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
  const info = parseCloudApiInfo(value, 'gateway_attestation');
  const parsed = parseApiResponse(
    CloudApiGatewayAttestationSchema,
    value,
    'gateway_attestation',
  );
  const base = parseAttestationEvidence(parsed, 'gateway_attestation', info);
  return { ...base, reportedQuoteData: parsed.report_data };
}

function parseModelAttestation(
  value: unknown,
  label: string,
): ModelAttestation {
  const info = parseCloudApiInfo(value, label);
  const parsed = parseApiResponse(CloudApiModelAttestationSchema, value, label);
  const base = parseAttestationEvidence(parsed, label, info);

  return {
    ...base,
    ...(parsed.nvidia_payload !== undefined
      ? { nvidiaPayload: parsed.nvidia_payload }
      : {}),
  };
}

type CloudApiAttestation =
  | CloudApiGatewayAttestation
  | CloudApiModelAttestation;
type CloudApiTcbInfoValue = CloudApiInfo['tcb_info'];

function parseAttestationEvidence(
  value: CloudApiAttestation,
  label: string,
  info: CloudApiInfo,
): AttestationEvidence {
  const appCompose = parseAppCompose(info.tcb_info, `${label}.info.tcb_info`);
  const signingAlgorithm = value.signing_algo;
  const signingAddress = value.signing_address;
  validateApiSigningAddress(
    signingAddress,
    signingAlgorithm,
    `${label}.signing_address`,
  );
  return {
    nonce: value.request_nonce,
    signer: {
      algorithm: signingAlgorithm,
      address: signingAddress,
    },
    intelQuote: value.intel_quote,
    eventLog: value.event_log,
    appCompose,
    ...(value.tls_cert_fingerprint !== undefined
      ? { declaredSpkiFingerprint: value.tls_cert_fingerprint }
      : {}),
    ...(value.report_data !== undefined
      ? { reportedQuoteData: value.report_data }
      : {}),
  };
}

function parseCloudApiInfo(value: unknown, label: string): CloudApiInfo {
  const envelope = parseApiResponse(
    CloudApiAttestationInfoEnvelopeSchema,
    value,
    label,
  );
  return parseApiResponse(CloudApiInfoSchema, envelope.info, `${label}.info`);
}

function parseCompletionSignatureLookup(
  value: unknown,
): CompletionSignatureLookup {
  const unavailableResponse = tryParse(
    CloudApiUnavailableSignatureResponseSchema,
    value,
  );
  if (unavailableResponse) {
    const unavailable: SignatureUnavailable = {
      errorCode: unavailableResponse.error_code,
      message: unavailableResponse.message,
    };
    return { status: 'unavailable', unavailable };
  }

  const response = parseApiResponse(
    CloudApiCompletionSignatureResponseSchema,
    value,
    'signature',
  );
  const signingAlgorithm = response.signing_algo;
  const signingAddress = response.signing_address;
  validateApiSigningAddress(
    signingAddress,
    signingAlgorithm,
    'signature.signing_address',
  );
  const base = {
    signedText: response.text,
    signature: response.signature,
    signer: { address: signingAddress, algorithm: signingAlgorithm },
  };
  return {
    status: 'found',
    signature: {
      ...base,
      kind: parseSignatureKind(response.signature_kind),
    },
  };
}

function parseSignatureKind(value: unknown): CompletionSignature['kind'] {
  if (value === 'provider_tee') {
    return value;
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

function parseAppCompose(value: CloudApiTcbInfoValue, label: string): string {
  if (typeof value === 'string') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(value);
    } catch {
      throw invalidResponse(label, 'JSON object', value);
    }
    return parseApiResponse(CloudApiTcbInfoSchema, parsed, label).app_compose;
  }
  return value.app_compose;
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
