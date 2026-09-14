import {
  decodeCompletionSignature,
  decodeGatewayAttestationReport,
  decodeModelAttestationReport,
} from '../boundaries/cloud-api';
import type { SigningAlgo, SigningIdentity } from '../types/attestation-common';
import type {
  CompletionSignature,
  CompletionSignatureReference,
} from '../types/chat';
import type {
  AttestationClientOptions,
  FetchCompletionSignatureParams,
  FetchedGatewayAttestation,
  FetchedModelAttestations,
  FetchGatewayAttestationParams,
  FetchModelAttestationsParams,
  FindModelAttestationForSignatureParams,
} from '../types/cloud-api';
import type { VerifiedModelAttestation } from '../types/verification';
import { generateNonce, hexToBuffer } from '../utils/common';
import {
  ApiError,
  isVerificationError,
  type ApiFailure,
} from '../utils/errors';

/** Set this on completion requests to reject model aliases before dispatch. */
export const NO_ALIASING_HEADER = 'x-no-aliasing';

/** Default production endpoint used when a helper does not select another one. */
export const DEFAULT_NEAR_AI_CLOUD_BASE_URL = 'https://cloud-api.near.ai/v1';

type ApiResource = Extract<
  ApiFailure,
  { code: 'api.transport_failed' }
>['details']['resource'];
type AttestationResource = 'model_attestation' | 'gateway_attestation';
type GetCloudApiJsonParams = {
  readonly url: URL;
  readonly resource: ApiResource;
  readonly extraHeaders?: HeadersInit;
};
type GetGatewayAttestationJsonParams = {
  readonly url: URL;
  readonly capturePeerSpkiFingerprint: boolean;
};
type FetchGatewayAttestationRequestParams = {
  readonly signingAlgo?: SigningAlgo;
  readonly includeSpkiFingerprint: boolean;
};
type GatewayAttestationJson = {
  readonly json: unknown;
  readonly peerSpkiFingerprint?: string;
};

/** Internal response shape used by the Node client to attach its TLS peer. */
export type GatewayAttestationHttpResponse = {
  readonly response: Response;
  readonly peerSpkiFingerprint?: string;
};

type CreateCloudApiRequestParams = {
  readonly url: URL;
  readonly extraHeaders?: HeadersInit;
};
type MergeCloudApiRequestHeadersParams = {
  readonly configuration: CloudApiRequestConfiguration;
  readonly requestHeaders?: HeadersInit;
};
type ReadCloudApiJsonParams = {
  readonly response: Response;
  readonly resource: ApiResource;
};
type ValidateApiSigningAddressParams = {
  readonly signingAddress: string;
  readonly signingAlgo?: SigningAlgo;
  readonly field: string;
};

/** Internal static request configuration shared by evidence and Chat clients. */
export type CloudApiRequestConfiguration = {
  readonly apiKey?: string;
  readonly defaultHeaders: Headers;
};

/** Read the static headers used for every SDK request. */
export function createCloudApiRequestConfiguration(
  options: AttestationClientOptions,
): CloudApiRequestConfiguration {
  try {
    return {
      apiKey: options.apiKey,
      defaultHeaders: new Headers(options.headers),
    };
  } catch (cause) {
    throw invalidHeaderInput('headers', cause);
  }
}

/** Merge configured and request-specific headers, with the direct API key last. */
export function mergeCloudApiRequestHeaders({
  configuration,
  requestHeaders,
}: MergeCloudApiRequestHeadersParams): Headers {
  try {
    const headers = new Headers(configuration.defaultHeaders);
    if (requestHeaders !== undefined) {
      for (const [name, value] of new Headers(requestHeaders)) {
        headers.set(name, value);
      }
    }
    if (configuration.apiKey !== undefined) {
      headers.set('authorization', `Bearer ${configuration.apiKey}`);
    }
    return headers;
  } catch (cause) {
    throw invalidHeaderInput(
      configuration.apiKey === undefined ? 'headers' : 'apiKey',
      cause,
    );
  }
}

/**
 * Shared Cloud API client implementation. Runtime-specific clients expose
 * their own Gateway-attestation options while sharing model and signature
 * requests.
 */
export class CloudApiClient {
  private readonly baseUrl: string;
  private readonly requestConfiguration: CloudApiRequestConfiguration;

  constructor(options: AttestationClientOptions) {
    this.requestConfiguration = createCloudApiRequestConfiguration(options);
    this.baseUrl = resolveCloudApiBaseUrl(options.baseUrl);
  }

  /**
   * Fetch NEAR model attestation candidates with a fresh client nonce.
   * Optionally narrow the report to a signing algorithm and signing address.
   * Every returned candidate is bound to the same fresh client nonce.
   */
  async fetchModelAttestations({
    model,
    signingAlgo,
    signingAddress,
  }: FetchModelAttestationsParams): Promise<FetchedModelAttestations> {
    if (signingAddress !== undefined) {
      validateApiSigningAddress({
        signingAddress,
        signingAlgo,
        field: 'signingAddress',
      });
    }
    const clientNonce = generateNonce();
    const url = new URL('attestation/report', this.baseUrl);
    url.searchParams.set('model', model);
    url.searchParams.set('provider', 'near');
    url.searchParams.set('nonce', clientNonce);
    url.searchParams.set('include_tls_fingerprint', 'false');
    if (signingAlgo !== undefined) {
      url.searchParams.set('signing_algo', signingAlgo);
    }
    if (signingAddress !== undefined) {
      url.searchParams.set('signing_address', signingAddress);
    }

    const attestations = decodeModelAttestationReport(
      await this.getCloudApiJson({
        url,
        resource: 'model_attestation',
        extraHeaders: { [NO_ALIASING_HEADER]: 'true' },
      }),
    );
    for (const attestation of attestations) {
      requireMatchingApiNonce({
        reportedNonce: attestation.nonce,
        requestedNonce: clientNonce,
        resource: 'model_attestation',
      });
    }
    return { attestations, clientBinding: { nonce: clientNonce } };
  }

  /**
   * Fetch standalone Gateway evidence. A returned SPKI fingerprint selects
   * the TLS-bound quote layout during `verifyGatewayAttestation`.
   */
  protected async fetchGatewayAttestationWithOptions({
    signingAlgo,
    includeSpkiFingerprint,
  }: FetchGatewayAttestationRequestParams): Promise<FetchedGatewayAttestation> {
    const clientNonce = generateNonce();
    const url = new URL('attestation/report', this.baseUrl);
    url.searchParams.set('nonce', clientNonce);
    if (signingAlgo !== undefined) {
      url.searchParams.set('signing_algo', signingAlgo);
    }
    url.searchParams.set(
      'include_tls_fingerprint',
      String(includeSpkiFingerprint),
    );
    const result = await this.getGatewayAttestationJson({
      url,
      capturePeerSpkiFingerprint: includeSpkiFingerprint,
    });
    const attestation = decodeGatewayAttestationReport(result.json);
    const responseIncludesSpkiFingerprint =
      attestation.spkiFingerprint !== undefined;
    if (responseIncludesSpkiFingerprint !== includeSpkiFingerprint) {
      throw new ApiError({
        code: 'api.invalid_response',
        details: {
          path: 'gateway_attestation.tls_cert_fingerprint',
          expected: includeSpkiFingerprint ? 'present' : 'missing',
          actual: responseIncludesSpkiFingerprint ? 'present' : 'missing',
        },
      });
    }
    requireMatchingApiNonce({
      reportedNonce: attestation.nonce,
      requestedNonce: clientNonce,
      resource: 'gateway_attestation',
    });
    return {
      attestation,
      clientBinding: {
        nonce: clientNonce,
        ...(result.peerSpkiFingerprint === undefined
          ? {}
          : { spkiFingerprint: result.peerSpkiFingerprint }),
      },
    };
  }

  /** Fetch one completion signature or throw when Cloud API does not provide one. */
  async fetchCompletionSignature({
    completionId,
    signingAlgo,
  }: FetchCompletionSignatureParams): Promise<CompletionSignature> {
    const url = new URL(
      `signature/${encodeURIComponent(completionId)}`,
      this.baseUrl,
    );
    if (signingAlgo !== undefined) {
      url.searchParams.set('signing_algo', signingAlgo);
    }
    return decodeCompletionSignature(
      await this.getCloudApiJson({
        url,
        resource: 'completion_signature',
      }),
    );
  }

  /**
   * Node overrides this to capture the TLS peer certificate for the exact
   * Gateway attestation request. Browser clients use standard Fetch.
   */
  protected async requestGatewayAttestation(
    request: Request,
    _capturePeerSpkiFingerprint: boolean,
  ): Promise<GatewayAttestationHttpResponse> {
    return { response: await fetch(request) };
  }

  /** Override this in a runtime-specific client to control ordinary API requests. */
  protected async requestCloudApi(request: Request): Promise<Response> {
    return fetch(request);
  }

  private async getCloudApiJson({
    url,
    resource,
    extraHeaders = {},
  }: GetCloudApiJsonParams): Promise<unknown> {
    const request = this.createCloudApiRequest({ url, extraHeaders });
    let response: Response;
    try {
      response = await this.requestCloudApi(request);
    } catch (cause) {
      if (isVerificationError(cause)) {
        throw cause;
      }
      throw new ApiError(
        {
          code: 'api.transport_failed',
          details: { resource, reason: 'request' },
          retryable: true,
        },
        { cause },
      );
    }

    return readCloudApiJson({ response, resource });
  }

  private async getGatewayAttestationJson({
    url,
    capturePeerSpkiFingerprint,
  }: GetGatewayAttestationJsonParams): Promise<GatewayAttestationJson> {
    const request = this.createCloudApiRequest({ url });
    let result: GatewayAttestationHttpResponse;
    try {
      result = await this.requestGatewayAttestation(
        request,
        capturePeerSpkiFingerprint,
      );
    } catch (cause) {
      throw new ApiError(
        {
          code: 'api.transport_failed',
          details: { resource: 'gateway_attestation', reason: 'request' },
          retryable: true,
        },
        { cause },
      );
    }

    return {
      json: await readCloudApiJson({
        response: result.response,
        resource: 'gateway_attestation',
      }),
      peerSpkiFingerprint: result.peerSpkiFingerprint,
    };
  }

  private createCloudApiRequest({
    url,
    extraHeaders = {},
  }: CreateCloudApiRequestParams): Request {
    const headers = mergeCloudApiRequestHeaders({
      configuration: this.requestConfiguration,
      requestHeaders: extraHeaders,
    });
    return new Request(url, { headers });
  }
}

function invalidHeaderInput(
  field: 'apiKey' | 'headers',
  cause: unknown,
): ApiError {
  return new ApiError(
    {
      code: 'api.invalid_input',
      details: {
        field,
        reason: 'invalid_header_value',
        expected: 'an HTTP header value',
      },
    },
    { cause },
  );
}

/**
 * Generic client for fetching attestation evidence and completion signatures
 * from NEAR AI Cloud. It owns the Cloud API configuration; verification
 * functions remain standalone.
 *
 * Standard Fetch does not expose the TLS peer certificate. Gateway evidence
 * therefore defaults to the signer-and-nonce quote layout in this client.
 */
export class AttestationClient extends CloudApiClient {
  async fetchGatewayAttestation({
    signingAlgo,
    includeSpkiFingerprint = false,
  }: FetchGatewayAttestationParams = {}): Promise<FetchedGatewayAttestation> {
    return this.fetchGatewayAttestationWithOptions({
      signingAlgo,
      includeSpkiFingerprint,
    });
  }
}

async function readCloudApiJson({
  response,
  resource,
}: ReadCloudApiJsonParams): Promise<unknown> {
  let body: string;
  try {
    body = await response.text();
  } catch (cause) {
    throw new ApiError(
      {
        code: 'api.transport_failed',
        details: { resource, reason: 'response_body' },
        retryable: true,
      },
      { cause },
    );
  }
  if (!response.ok) {
    throw new ApiError({
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
        code: 'api.invalid_json',
        details: { resource },
      },
      { cause },
    );
  }
}

/**
 * Select the single verified model attestation whose signer matches a
 * provider_tee completion signature. This is a selection helper; it does not
 * perform another attestation or completion-signature verification.
 */
export function findModelAttestationForSignature({
  attestations,
  signature,
}: FindModelAttestationForSignatureParams): VerifiedModelAttestation {
  const signer = requireProviderSignature(signature);
  const signerAddress = validateApiSigningAddress({
    signingAddress: signer.signingAddress,
    signingAlgo: signer.signingAlgo,
    field: 'signature.signer.signingAddress',
  });
  const matches: VerifiedModelAttestation[] = [];
  for (const [index, attestation] of attestations.entries()) {
    const candidateSigner = attestation.signer;
    if (
      candidateSigner.signingAlgo === signer.signingAlgo &&
      validateApiSigningAddress({
        signingAddress: candidateSigner.signingAddress,
        signingAlgo: candidateSigner.signingAlgo,
        field: `attestations[${index}].signer.signingAddress`,
      }).equals(signerAddress)
    ) {
      matches.push(attestation);
    }
  }

  if (matches.length === 0) {
    throw new ApiError({
      code: 'api.model_attestation_signer_not_found',
    });
  }
  if (matches.length !== 1) {
    throw new ApiError({
      code: 'api.ambiguous_model_attestation_signer',
      details: {
        matchingCount: matches.length,
        totalCount: attestations.length,
      },
    });
  }
  return matches[0];
}

function requireProviderSignature(
  signature: CompletionSignatureReference,
): SigningIdentity {
  if (signature.kind !== 'provider_tee') {
    throw new ApiError({
      code: 'api.invalid_input',
      details: {
        field: 'signature.kind',
        reason: 'unsupported_value',
        expected: 'provider_tee',
        actual: signature.kind,
      },
    });
  }
  return signature.signer;
}

function validateApiSigningAddress({
  signingAddress,
  signingAlgo,
  field,
}: ValidateApiSigningAddressParams): ReturnType<typeof hexToBuffer> {
  let address: ReturnType<typeof hexToBuffer>;
  try {
    address = hexToBuffer(signingAddress);
  } catch (cause) {
    throw new ApiError(
      {
        code: 'api.invalid_input',
        details: {
          field,
          reason: 'invalid_hex',
          expected: 'a hexadecimal signing address',
        },
      },
      { cause },
    );
  }
  const allowedLengths =
    signingAlgo === undefined ? [20, 32] : [signingAlgo === 'ecdsa' ? 20 : 32];
  if (!allowedLengths.includes(address.length)) {
    const expected =
      allowedLengths.length === 1
        ? `${allowedLengths[0]}-byte hexadecimal signing address`
        : '20- or 32-byte hexadecimal signing address';
    throw new ApiError({
      code: 'api.invalid_input',
      details: {
        field,
        reason: 'wrong_length',
        expected,
        actual: `${address.length} bytes`,
      },
    });
  }
  return address;
}

export function resolveCloudApiBaseUrl(
  baseUrl = DEFAULT_NEAR_AI_CLOUD_BASE_URL,
): string {
  let resolvedBaseUrl: URL;
  try {
    resolvedBaseUrl = new URL(baseUrl);
  } catch {
    throw invalidBaseUrl();
  }
  if (
    (resolvedBaseUrl.protocol !== 'http:' &&
      resolvedBaseUrl.protocol !== 'https:') ||
    resolvedBaseUrl.hostname === '' ||
    resolvedBaseUrl.search !== '' ||
    resolvedBaseUrl.hash !== ''
  ) {
    throw invalidBaseUrl();
  }
  if (!resolvedBaseUrl.pathname.endsWith('/')) {
    resolvedBaseUrl.pathname = `${resolvedBaseUrl.pathname}/`;
  }
  return resolvedBaseUrl.toString();
}

function invalidBaseUrl(): ApiError {
  return new ApiError({
    code: 'api.invalid_input',
    details: {
      field: 'baseUrl',
      reason: 'invalid_url',
      expected: 'an absolute HTTP(S) URL without a query or fragment',
    },
  });
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

type RequireMatchingApiNonceParams = {
  readonly reportedNonce: string;
  readonly requestedNonce: string;
  readonly resource: AttestationResource;
};

/** Reject a response that does not echo the nonce sent in its request. */
function requireMatchingApiNonce({
  reportedNonce,
  requestedNonce,
  resource,
}: RequireMatchingApiNonceParams): void {
  if (
    decodeApiNonce(reportedNonce, `${resource}.request_nonce`).equals(
      decodeApiNonce(requestedNonce, 'nonce'),
    )
  ) {
    return;
  }
  throw new ApiError({
    code: 'api.nonce_mismatch',
    details: { resource },
  });
}

function decodeApiNonce(
  value: string,
  path: string,
): ReturnType<typeof hexToBuffer> {
  try {
    return hexToBuffer(value);
  } catch (cause) {
    throw new ApiError(
      {
        code: 'api.invalid_response',
        details: {
          path,
          expected: 'a hexadecimal nonce',
          actual: 'invalid',
        },
      },
      { cause },
    );
  }
}
