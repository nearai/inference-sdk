import type { GatewayAttestation } from '../types/attestation-gateway';
import type { ModelAttestation } from '../types/attestation-model';
import type {
  AttestationEvidence,
  SigningAlgo,
  SigningIdentity,
} from '../types/attestation-common';
import type {
  CompletionSignature,
  CompletionSignatureReference,
  CompletionSignatureLookup,
  SignatureUnavailable,
} from '../types/chat';
import type {
  CloudApiGatewayAttestation,
  CloudApiInfo,
  CloudApiModelAttestation,
  FetchCompletionSignatureInput,
  FetchedGatewayAttestation,
  FetchedModelAttestation,
  FetchedModelAttestations,
  FetchGatewayAttestationInput,
  FetchModelAttestationForSignatureInput,
  FetchModelAttestationsInput,
  FindModelAttestationForSignatureInput,
  NearAiCloudClientOptions,
  NearAiCloudFetch,
  ResponseLike,
} from '../types/cloud-api';
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
  ResponseBodySchema,
  ResponseLikeSchema,
} from '../schemas';
import {
  generateNonce,
  normalizeHex,
  requireByteLength,
} from '../utils/common';
import { ApiError, type ApiFailure, VerificationError } from '../utils/errors';
import {
  inputError,
  optionalInputString,
  rejectUnknownInputKeys,
  requireInputArray,
  requireInputFunction,
  requireInputObject,
  requireInputString,
} from '../utils/input';
import { parseApiResponse, tryParse } from '../utils/schema';

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
   * Fetch NEAR model attestation candidates with a fresh client nonce.
   * Optionally narrow the report to a signing algorithm and signing address.
   * Currently returns exactly one candidate.
   */
  async fetchModelAttestations(
    input: FetchModelAttestationsInput,
  ): Promise<FetchedModelAttestations> {
    const request = parseModelAttestationsRequest(input);
    const clientNonce = generateNonce();
    const url = this.endpoint('attestation/report');
    url.searchParams.set('model', request.model);
    url.searchParams.set('provider', 'near');
    url.searchParams.set('nonce', clientNonce);
    if (request.signingAlgo !== undefined) {
      url.searchParams.set('signing_algo', request.signingAlgo);
    }
    if (request.signingAddress !== undefined) {
      url.searchParams.set('signing_address', request.signingAddress);
    }

    const attestations = parseModelAttestations(
      await this.getJson(url, 'model_attestation', {
        [NO_ALIASING_HEADER]: 'true',
      }),
    );
    for (const attestation of attestations) {
      requireMatchingApiNonce(
        attestation.nonce,
        clientNonce,
        'model_attestation',
      );
    }
    return { attestations, nonce: clientNonce };
  }

  /**
   * Fetch model attestation candidates for a provider_tee signature, then
   * select the one whose advertised signer matches the signature signer.
   */
  async fetchModelAttestationForSignature(
    input: FetchModelAttestationForSignatureInput,
  ): Promise<FetchedModelAttestation> {
    const request = parseModelAttestationForSignatureRequest(input);
    const fetched = await this.fetchModelAttestations({
      model: request.model,
      signingAlgo: request.signature.signer.signingAlgo,
      signingAddress: request.signature.signer.signingAddress,
    });
    return {
      attestation: selectModelAttestationForSigner(
        fetched.attestations,
        request.signature.signer,
      ),
      nonce: fetched.nonce,
    };
  }

  /**
   * Fetch standalone gateway evidence. The caller must independently observe
   * the TLS peer fingerprint for this attestation request.
   */
  async fetchGatewayAttestation(
    input: FetchGatewayAttestationInput = {},
  ): Promise<FetchedGatewayAttestation> {
    const request = parseGatewayAttestationRequest(input);
    const clientNonce = generateNonce();
    const url = this.endpoint('attestation/report');
    url.searchParams.set('nonce', clientNonce);
    url.searchParams.set('signing_algo', request.signingAlgo);
    url.searchParams.set('include_tls_fingerprint', 'true');
    const report = parseApiResponse(
      CloudApiGatewayAttestationResponseSchema,
      await this.getJson(url, 'gateway_attestation'),
      'gateway attestation report',
    );
    const attestation = parseGatewayAttestation(report.gateway_attestation);
    requireMatchingApiNonce(
      attestation.nonce,
      clientNonce,
      'gateway_attestation',
    );
    return { attestation, nonce: clientNonce };
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
    if (request.signingAlgo !== undefined) {
      url.searchParams.set('signing_algo', request.signingAlgo);
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
 * provider_tee completion signature. It does not verify the quote or
 * completion signature.
 */
export function findModelAttestationForSignature(
  input: FindModelAttestationForSignatureInput,
): ModelAttestation {
  const value = requireInputObject(input, 'input');
  rejectUnknownInputKeys(value, 'input', ['attestations', 'signature']);
  const signature = requireSignatureSigner(value.signature, 'provider_tee');
  const attestations = requireInputArray(
    value.attestations,
    'attestations',
  ) as readonly ModelAttestation[];
  return selectModelAttestationForSigner(attestations, signature.signer);
}

function selectModelAttestationForSigner(
  attestations: readonly ModelAttestation[],
  signer: SigningIdentity,
): ModelAttestation {
  const matches: ModelAttestation[] = [];
  for (const [index, attestation] of attestations.entries()) {
    const candidate = requireInputObject(attestation, `attestations[${index}]`);
    const candidateSigner = parseSigningIdentity(
      candidate.signer,
      `attestations[${index}].signer`,
    );
    if (
      candidateSigner.signingAlgo === signer.signingAlgo &&
      normalizeHex(candidateSigner.signingAddress) ===
        normalizeHex(signer.signingAddress)
    ) {
      matches.push(attestation);
    }
  }

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
        totalCount: attestations.length,
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
  const value = requireInputObject(options, 'options');
  rejectUnknownInputKeys(value, 'options', ['baseUrl', 'apiKey', 'fetch']);
  const baseUrl = optionalInputString(value.baseUrl, 'baseUrl');
  const fetchImpl =
    value.fetch === undefined
      ? fetch
      : (requireInputFunction(value.fetch, 'fetch') as NearAiCloudFetch);

  return {
    baseUrl: validateBaseUrl(
      baseUrl === undefined ? DEFAULT_NEAR_AI_CLOUD_BASE_URL : baseUrl,
    ),
    apiKey: validateApiKey(requireInputString(value.apiKey, 'apiKey')),
    fetch: fetchImpl,
  };
}

type ParsedModelAttestationsRequest = {
  model: string;
  signingAlgo?: SigningAlgo;
  signingAddress?: string;
};

function parseModelAttestationsRequest(
  input: unknown,
): ParsedModelAttestationsRequest {
  const value = requireInputObject(input, 'input');
  rejectUnknownInputKeys(value, 'input', [
    'model',
    'signingAlgo',
    'signingAddress',
  ]);
  const signingAlgo = optionalSigningAlgo(value.signingAlgo, 'signingAlgo');
  const signingAddress = optionalInputString(
    value.signingAddress,
    'signingAddress',
  );

  return {
    model: requireNonEmptyString(
      requireInputString(value.model, 'model'),
      'model',
    ),
    ...(signingAlgo === undefined ? {} : { signingAlgo }),
    ...(signingAddress === undefined
      ? {}
      : {
          signingAddress: validateModelAttestationSigningAddress(
            signingAddress,
            signingAlgo,
            'signingAddress',
          ),
        }),
  };
}

type ParsedModelAttestationForSignatureRequest = {
  model: string;
  signature: SignatureSigner;
};

function parseModelAttestationForSignatureRequest(
  input: unknown,
): ParsedModelAttestationForSignatureRequest {
  const value = requireInputObject(input, 'input');
  rejectUnknownInputKeys(value, 'input', ['model', 'signature']);

  return {
    model: requireNonEmptyString(
      requireInputString(value.model, 'model'),
      'model',
    ),
    signature: requireSignatureSigner(value.signature, 'provider_tee'),
  };
}

type ParsedGatewayAttestationRequest = {
  signingAlgo: SigningAlgo;
};

function parseGatewayAttestationRequest(
  input: unknown,
): ParsedGatewayAttestationRequest {
  const value = requireInputObject(input, 'input');
  rejectUnknownInputKeys(value, 'input', ['signingAlgo']);

  return {
    signingAlgo:
      optionalSigningAlgo(value.signingAlgo, 'signingAlgo') ?? 'ed25519',
  };
}

type ParsedCompletionSignatureRequest = FetchCompletionSignatureInput;

function parseCompletionSignatureRequest(
  input: unknown,
): ParsedCompletionSignatureRequest {
  const value = requireInputObject(input, 'input');
  rejectUnknownInputKeys(value, 'input', ['completionId', 'signingAlgo']);
  const signingAlgo = optionalSigningAlgo(value.signingAlgo, 'signingAlgo');

  return {
    completionId: requireNonEmptyString(
      requireInputString(value.completionId, 'completionId'),
      'completionId',
    ),
    ...(signingAlgo === undefined ? {} : { signingAlgo }),
  };
}

type SignatureSigner = CompletionSignatureReference;

function requireSignatureSigner(
  value: unknown,
  expectedKind: CompletionSignatureReference['kind'],
): SignatureSigner {
  const signature = requireInputObject(value, 'signature');
  rejectUnknownInputKeys(signature, 'signature', [
    'kind',
    'signer',
    'signedText',
    'signature',
  ]);
  const kind = requireSignatureKind(signature.kind, 'signature.kind');
  if (kind !== expectedKind) {
    throw new VerificationError({
      phase: 'signature',
      code: 'signature.kind_mismatch',
      details: { expected: expectedKind, actual: kind },
    });
  }
  return {
    kind,
    signer: parseSigningIdentity(signature.signer, 'signature.signer'),
  };
}

function parseSigningIdentity(value: unknown, field: string): SigningIdentity {
  const signer = requireInputObject(value, field);
  rejectUnknownInputKeys(signer, field, ['signingAlgo', 'signingAddress']);
  const signingAlgo = requireSigningAlgo(
    signer.signingAlgo,
    `${field}.signingAlgo`,
  );
  return {
    signingAlgo,
    signingAddress: validateSigningAddress(
      requireInputString(signer.signingAddress, `${field}.signingAddress`),
      signingAlgo,
      `${field}.signingAddress`,
    ),
  };
}

function requireSignatureKind(
  value: unknown,
  field: string,
): CompletionSignature['kind'] {
  if (value === 'provider_tee' || value === 'gateway') {
    return value;
  }
  throw inputError(
    field,
    value === undefined ? 'missing' : 'unsupported_value',
    {
      expected: "'provider_tee' or 'gateway'",
    },
  );
}

function requireSigningAlgo(value: unknown, field: string): SigningAlgo {
  if (value === 'ecdsa' || value === 'ed25519') {
    return value;
  }
  throw inputError(
    field,
    value === undefined ? 'missing' : 'unsupported_value',
    {
      expected: "'ecdsa' or 'ed25519'",
    },
  );
}

function optionalSigningAlgo(
  value: unknown,
  field: string,
): SigningAlgo | undefined {
  return value === undefined ? undefined : requireSigningAlgo(value, field);
}

function validateSigningAddress(
  signingAddress: string,
  signingAlgo: SigningAlgo,
  field: string,
): string {
  requireByteLength(signingAddress, signingAlgo === 'ecdsa' ? 20 : 32, field);
  return signingAddress;
}

function validateModelAttestationSigningAddress(
  signingAddress: string,
  signingAlgo: SigningAlgo | undefined,
  field: string,
): string {
  if (signingAlgo !== undefined) {
    return validateSigningAddress(signingAddress, signingAlgo, field);
  }

  const actualBytes = normalizeHex(signingAddress).length / 2;
  if (actualBytes === 20 || actualBytes === 32) {
    return signingAddress;
  }
  throw inputError(field, 'wrong_length', {
    expected: '20-byte ECDSA or 32-byte Ed25519 hexadecimal signing address',
    actualBytes,
  });
}

function validateBaseUrl(baseUrl: string): string {
  try {
    // WHATWG URL normalizes a trailing bare `?` or `#` to an empty search/hash.
    // Reject the raw delimiters before that normalization so appending a path
    // separator cannot accidentally turn the query or fragment into the base.
    if (baseUrl.includes('?') || baseUrl.includes('#')) {
      throw new TypeError('invalid base URL');
    }
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
  const signingAlgo = value.signing_algo;
  const signingAddress = value.signing_address;
  validateApiSigningAddress(
    signingAddress,
    signingAlgo,
    `${label}.signing_address`,
  );
  return {
    nonce: validateApiNonce(value.request_nonce, `${label}.request_nonce`),
    signer: {
      signingAlgo,
      signingAddress,
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
  const signingAlgo = response.signing_algo;
  const signingAddress = response.signing_address;
  validateApiSigningAddress(
    signingAddress,
    signingAlgo,
    'signature.signing_address',
  );
  const base = {
    signedText: response.text,
    signature: response.signature,
    signer: { signingAlgo, signingAddress },
  };
  return {
    status: 'found',
    signature: {
      ...base,
      kind: response.signature_kind,
    },
  };
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
  signingAddress: string,
  signingAlgo: SigningAlgo,
  label: string,
): void {
  const normalized =
    signingAddress.startsWith('0x') || signingAddress.startsWith('0X')
      ? signingAddress.slice(2)
      : signingAddress;
  const expectedBytes = signingAlgo === 'ecdsa' ? 20 : 32;
  if (
    normalized.length !== expectedBytes * 2 ||
    !/^[0-9a-fA-F]+$/.test(normalized)
  ) {
    throw invalidResponse(
      label,
      `${expectedBytes}-byte hexadecimal signing address`,
      signingAddress,
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
