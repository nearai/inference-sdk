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
  FetchModelAttestationForSignatureInputSchema,
  FetchModelAttestationsInputSchema,
  CloudApiUnavailableSignatureResponseSchema,
  FetchCompletionSignatureInputSchema,
  FetchGatewayAttestationInputSchema,
  FindModelAttestationForSignerInputSchema,
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
  FetchModelAttestationForSignatureInput,
  FetchModelAttestationsInput,
  FindModelAttestationForSignerInput,
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
  FetchModelAttestationForSignatureInput,
  FetchModelAttestationsInput,
  FindModelAttestationForSignerInput,
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
type AttestationResource = 'model_attestation' | 'gateway_attestation';

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
   * Fetch NEAR model attestation candidates for one model and signing
   * algorithm. Optionally narrow the report to a signing address. Cloud API
   * currently returns exactly one candidate.
   */
  async fetchModelAttestations(
    input: FetchModelAttestationsInput,
  ): Promise<readonly ModelAttestation[]> {
    const request = parseModelAttestationsRequest(input);
    const url = this.endpoint('attestation/report');
    setModelAttestationQuery(
      url,
      request.nonce,
      request.algorithm,
      request.signingAddress,
    );
    url.searchParams.set('model', request.model);
    url.searchParams.set('provider', 'near');

    const attestations = parseModelAttestations(
      await this.getJson(url, 'model_attestation', {
        [NO_ALIASING_HEADER]: 'true',
      }),
    );
    for (const attestation of attestations) {
      requireMatchingApiNonce(
        attestation.nonce,
        request.nonce,
        'model_attestation',
      );
    }
    return attestations;
  }

  /**
   * Fetch model attestation candidates for a provider_tee signature, then
   * select the one whose advertised signer matches the signature signer.
   */
  async fetchModelAttestationForSignature(
    input: FetchModelAttestationForSignatureInput,
  ): Promise<ModelAttestation> {
    const request = parseModelAttestationForSignatureRequest(input);
    const attestations = await this.fetchModelAttestations({
      model: request.model,
      nonce: request.nonce,
      algorithm: request.signature.signer.algorithm,
      signingAddress: request.signature.signer.address,
    });
    return findModelAttestationForSigner({
      attestations,
      signer: request.signature.signer,
    });
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
    const attestation = parseGatewayAttestation(report.gateway_attestation);
    requireMatchingApiNonce(
      attestation.nonce,
      request.nonce,
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

/**
 * Select the single model attestation whose advertised signer matches a
 * requested signer. It does not verify the quote or completion signature.
 */
export function findModelAttestationForSigner(
  input: FindModelAttestationForSignerInput,
): ModelAttestation {
  const parsed = parsePublicInput(
    FindModelAttestationForSignerInputSchema,
    input,
    'input',
  );
  const signer = parseSigningIdentity(parsed.signer, 'signer');
  const matches = parsed.attestations
    .map((attestation, index) => ({
      ...attestation,
      signer: parseSigningIdentity(
        attestation.signer,
        `attestations[${index}].signer`,
      ),
    }))
    .filter(
      (attestation) =>
        attestation.signer.algorithm === signer.algorithm &&
        normalizeHex(attestation.signer.address) ===
          normalizeHex(signer.address),
    );

  if (matches.length === 0) {
    throw new ApiError({
      phase: 'api',
      code: 'api.attestation_signer_mismatch',
      details: { resource: 'model_attestation' },
    });
  }
  if (matches.length !== 1) {
    throw new ApiError({
      phase: 'api',
      code: 'api.ambiguous_model_attestation_signer',
      details: {
        matchingCount: matches.length,
        totalCount: parsed.attestations.length,
      },
    });
  }
  return matches[0];
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

type ParsedModelAttestationsRequest = {
  model: string;
  nonce: string;
  algorithm?: SigningAlgorithm;
  signingAddress?: string;
};

function parseModelAttestationsRequest(
  input: unknown,
): ParsedModelAttestationsRequest {
  const parsed = parsePublicInput(
    FetchModelAttestationsInputSchema,
    input,
    'input',
  );

  const signingAddress =
    parsed.signingAddress === undefined
      ? undefined
      : validateModelAttestationSigningAddress(
          parsed.signingAddress,
          parsed.algorithm,
          'signingAddress',
        );

  return {
    model: requireNonEmptyString(parsed.model, 'model'),
    nonce: validateNonce(parsed.nonce),
    ...(parsed.algorithm === undefined ? {} : { algorithm: parsed.algorithm }),
    ...(signingAddress === undefined ? {} : { signingAddress }),
  };
}

type ParsedModelAttestationForSignatureRequest = {
  model: string;
  nonce: string;
  signature: CompletionSignature;
};

function parseModelAttestationForSignatureRequest(
  input: unknown,
): ParsedModelAttestationForSignatureRequest {
  const parsed = parsePublicInput(
    FetchModelAttestationForSignatureInputSchema,
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

function parseSigningIdentity(
  signer: SigningIdentity,
  field = 'signature.signer',
): SigningIdentity {
  return {
    algorithm: signer.algorithm,
    address: validateSigningAddress(
      signer.address,
      signer.algorithm,
      `${field}.address`,
    ),
  };
}

function validateSigningAddress(
  address: string,
  algorithm: SigningAlgorithm,
  field: string,
): string {
  requireByteLength(address, algorithm === 'ecdsa' ? 20 : 32, field);
  return address;
}

function validateModelAttestationSigningAddress(
  address: string,
  algorithm: SigningAlgorithm | undefined,
  field: string,
): string {
  if (algorithm !== undefined) {
    return validateSigningAddress(address, algorithm, field);
  }

  const actualBytes = normalizeHex(address).length / 2;
  if (actualBytes === 20 || actualBytes === 32) {
    return address;
  }
  throw inputError(field, 'wrong_length', {
    expected: '20-byte ECDSA or 32-byte Ed25519 hexadecimal signing address',
    actualBytes,
  });
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

function setModelAttestationQuery(
  url: URL,
  nonce: string,
  algorithm: SigningAlgorithm | undefined,
  signingAddress: string | undefined,
): void {
  url.searchParams.set('nonce', nonce);
  if (algorithm !== undefined) {
    url.searchParams.set('signing_algo', algorithm);
  }
  if (signingAddress !== undefined) {
    url.searchParams.set('signing_address', signingAddress);
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

function parseModelAttestations(value: unknown): readonly ModelAttestation[] {
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
  return rawAttestations.map((attestation, index) =>
    parseModelAttestation(attestation, `model_attestations[${index}]`),
  );
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
    nonce: validateApiNonce(value.request_nonce, `${label}.request_nonce`),
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

function validateApiNonce(value: string, label: string): string {
  const normalized =
    value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  if (normalized.length !== 64 || !/^[0-9a-fA-F]+$/.test(normalized)) {
    throw invalidResponse(label, '32-byte hexadecimal nonce', value);
  }
  return value;
}

/** Reject a response that does not echo the nonce sent in its request. */
function requireMatchingApiNonce(
  reportedNonce: string,
  requestedNonce: string,
  resource: AttestationResource,
): void {
  if (normalizeHex(reportedNonce) === requestedNonce) {
    return;
  }
  throw new ApiError({
    phase: 'api',
    code: 'api.nonce_mismatch',
    details: { resource },
  });
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
