import type { ModelAttestation } from '../types/attestation-model';
import type { SigningIdentity } from '../types/attestation-common';
import type {
  CompletionSignature,
  CompletionSignatureReference,
  CompletionSignatureLookup,
} from '../types/chat';
import type {
  FetchCompletionSignatureParams,
  FetchedGatewayAttestation,
  FetchedModelAttestation,
  FetchedModelAttestations,
  FetchGatewayAttestationParams,
  FetchModelAttestationForSignatureParams,
  FetchModelAttestationsParams,
  FindModelAttestationForSignatureParams,
  LookupCompletionSignatureParams,
} from '../types/cloud-api';
import {
  decodeCompletionSignatureLookup,
  decodeGatewayAttestationReport,
  decodeModelAttestationReport,
} from '../boundaries/cloud-api';
import { generateNonce, hexToBuffer } from '../utils/common';
import { ApiError, type ApiFailure, VerificationError } from '../utils/errors';

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
  apiKey: string;
  url: URL;
  resource: ApiResource;
  extraHeaders?: HeadersInit;
};
type GetGatewayAttestationJsonParams = {
  apiKey: string;
  url: URL;
  requester: GatewayAttestationRequester;
};
type GatewayAttestationJson = {
  json: unknown;
  peerSpkiFingerprint?: string;
};
type GatewayAttestationRequester = (
  request: Request,
) => Promise<GatewayAttestationResponse>;
type GatewayAttestationResponse = {
  response: Response;
  peerSpkiFingerprint?: string;
};
type CreateCloudApiRequestParams = {
  apiKey: string;
  url: URL;
  extraHeaders?: HeadersInit;
};
type ReadCloudApiJsonParams = {
  response: Response;
  resource: ApiResource;
};

/**
 * Fetch NEAR model attestation candidates with a fresh client nonce.
 * Optionally narrow the report to a signing algorithm and signing address.
 * Currently returns exactly one candidate.
 */
export async function fetchModelAttestations({
  apiKey,
  baseUrl,
  model,
  signingAlgo,
  signingAddress,
}: FetchModelAttestationsParams): Promise<FetchedModelAttestations> {
  const clientNonce = generateNonce();
  const url = new URL('attestation/report', resolveCloudApiBaseUrl(baseUrl));
  url.searchParams.set('model', model);
  url.searchParams.set('provider', 'near');
  url.searchParams.set('nonce', clientNonce);
  if (signingAlgo !== undefined) {
    url.searchParams.set('signing_algo', signingAlgo);
  }
  if (signingAddress !== undefined) {
    url.searchParams.set('signing_address', signingAddress);
  }

  const attestations = decodeModelAttestationReport(
    await getCloudApiJson({
      apiKey,
      url,
      resource: 'model_attestation',
      extraHeaders: { [NO_ALIASING_HEADER]: 'true' },
    }),
  );
  if (attestations.length !== 1) {
    throw new ApiError({
      code: 'api.unexpected_model_attestation_count',
      details: { actualCount: attestations.length },
    });
  }
  for (const attestation of attestations) {
    requireMatchingApiNonce({
      reportedNonce: attestation.nonce,
      requestedNonce: clientNonce,
      resource: 'model_attestation',
    });
  }
  return { attestations, nonce: clientNonce };
}

/**
 * Fetch model attestation candidates for a provider_tee signature, then
 * select the one whose advertised signer matches the signature signer.
 */
export async function fetchModelAttestationForSignature({
  apiKey,
  baseUrl,
  model,
  signature,
}: FetchModelAttestationForSignatureParams): Promise<FetchedModelAttestation> {
  assertSignatureKind(signature, 'provider_tee');
  const fetched = await fetchModelAttestations({
    apiKey,
    baseUrl,
    model,
    signingAlgo: signature.signer.signingAlgo,
    signingAddress: signature.signer.signingAddress,
  });
  return {
    attestation: findModelAttestationForSignature({
      attestations: fetched.attestations,
      signature,
    }),
    nonce: fetched.nonce,
  };
}

/**
 * Fetch standalone Gateway evidence using the runtime's standard Fetch API.
 * Browser runtimes can verify the quote-bound TLS key but cannot inspect the
 * peer certificate for this request.
 */
export function fetchGatewayAttestation(
  params: FetchGatewayAttestationParams,
): Promise<FetchedGatewayAttestation> {
  return fetchGatewayAttestationWithRequester(params, async (request) => ({
    response: await fetch(request),
  }));
}

/** Internal shared implementation used by the browser and Node entry points. */
export async function fetchGatewayAttestationWithRequester(
  { apiKey, baseUrl, signingAlgo = 'ed25519' }: FetchGatewayAttestationParams,
  requester: GatewayAttestationRequester,
): Promise<FetchedGatewayAttestation> {
  const clientNonce = generateNonce();
  const url = new URL('attestation/report', resolveCloudApiBaseUrl(baseUrl));
  url.searchParams.set('nonce', clientNonce);
  url.searchParams.set('signing_algo', signingAlgo);
  url.searchParams.set('include_tls_fingerprint', 'true');
  const result = await getGatewayAttestationJson({ apiKey, url, requester });
  const attestation = decodeGatewayAttestationReport(result.json);
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
        : { peerSpkiFingerprint: result.peerSpkiFingerprint }),
    },
  };
}

/**
 * Look up one completion signature without polling. Use this when an
 * application needs to handle an unavailable signature itself.
 */
export async function lookupCompletionSignature({
  apiKey,
  baseUrl,
  completionId,
  signingAlgo,
}: LookupCompletionSignatureParams): Promise<CompletionSignatureLookup> {
  const url = new URL(
    `signature/${encodeURIComponent(completionId)}`,
    resolveCloudApiBaseUrl(baseUrl),
  );
  if (signingAlgo !== undefined) {
    url.searchParams.set('signing_algo', signingAlgo);
  }
  return decodeCompletionSignatureLookup(
    await getCloudApiJson({
      apiKey,
      url,
      resource: 'completion_signature',
    }),
  );
}

/** Fetch one completion signature or throw when Cloud API does not provide one. */
export async function fetchCompletionSignature({
  apiKey,
  baseUrl,
  completionId,
  signingAlgo,
}: FetchCompletionSignatureParams): Promise<CompletionSignature> {
  const lookup = await lookupCompletionSignature({
    apiKey,
    baseUrl,
    completionId,
    signingAlgo,
  });
  if (lookup.status === 'found') {
    return lookup.signature;
  }
  throw new ApiError({
    code: 'api.completion_signature_unavailable',
    details: { providerErrorCode: lookup.unavailable.errorCode },
  });
}

async function getCloudApiJson({
  apiKey,
  url,
  resource,
  extraHeaders = {},
}: GetCloudApiJsonParams): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(
      createCloudApiRequest({ apiKey, url, extraHeaders }),
    );
  } catch (cause) {
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

async function getGatewayAttestationJson({
  apiKey,
  url,
  requester,
}: GetGatewayAttestationJsonParams): Promise<GatewayAttestationJson> {
  const request = createCloudApiRequest({ apiKey, url });
  let result: GatewayAttestationResponse;
  try {
    result = await requester(request);
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

function createCloudApiRequest({
  apiKey,
  url,
  extraHeaders = {},
}: CreateCloudApiRequestParams): Request {
  const headers = new Headers(extraHeaders);
  headers.set('authorization', `Bearer ${apiKey}`);
  return new Request(url, { headers });
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
 * Select the single model attestation whose advertised signer matches a
 * provider_tee completion signature. It does not verify the quote or
 * completion signature.
 */
export function findModelAttestationForSignature({
  attestations,
  signature,
}: FindModelAttestationForSignatureParams): ModelAttestation {
  assertSignatureKind(signature, 'provider_tee');
  return selectModelAttestationForSigner(attestations, signature.signer);
}

function selectModelAttestationForSigner(
  attestations: readonly ModelAttestation[],
  signer: SigningIdentity,
): ModelAttestation {
  const matches: ModelAttestation[] = [];
  for (const attestation of attestations) {
    const candidateSigner = attestation.signer;
    if (
      candidateSigner.signingAlgo === signer.signingAlgo &&
      hexToBuffer(candidateSigner.signingAddress).equals(
        hexToBuffer(signer.signingAddress),
      )
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

function assertSignatureKind(
  signature: CompletionSignatureReference,
  expectedKind: CompletionSignatureReference['kind'],
): void {
  if (signature.kind !== expectedKind) {
    throw new VerificationError({
      code: 'signature.kind_mismatch',
      details: { expected: expectedKind, actual: signature.kind },
    });
  }
}

function resolveCloudApiBaseUrl(
  baseUrl = DEFAULT_NEAR_AI_CLOUD_BASE_URL,
): string {
  const resolvedBaseUrl = new URL(baseUrl);
  if (!resolvedBaseUrl.pathname.endsWith('/')) {
    resolvedBaseUrl.pathname = `${resolvedBaseUrl.pathname}/`;
  }
  return resolvedBaseUrl.toString();
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
  reportedNonce: string;
  requestedNonce: string;
  resource: AttestationResource;
};

/** Reject a response that does not echo the nonce sent in its request. */
function requireMatchingApiNonce({
  reportedNonce,
  requestedNonce,
  resource,
}: RequireMatchingApiNonceParams): void {
  if (hexToBuffer(reportedNonce).equals(hexToBuffer(requestedNonce))) {
    return;
  }
  throw new ApiError({
    code: 'api.nonce_mismatch',
    details: { resource },
  });
}
