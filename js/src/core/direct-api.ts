import {
  decodeDirectModelAttestations,
  decodeDirectCompletionSignature,
} from '../boundaries/direct-api';
import type { CompletionSignature } from '../types/chat';
import type { FetchCompletionSignatureParams } from '../types/cloud-api';
import type {
  DirectAttestationClientOptions,
  FetchDirectModelAttestationsParams,
  FetchedDirectModelAttestations,
  NodeFetchDirectModelAttestationsParams,
} from '../types/direct-api';
import { generateNonce } from '../utils/common';
import { ApiError, isVerificationError } from '../utils/errors';
import {
  type CloudApiRequestConfiguration,
  createCloudApiRequestConfiguration,
  mergeCloudApiRequestHeaders,
  readCloudApiJson,
  requireMatchingApiNonce,
  resolveCloudApiBaseUrl,
  validateApiSigningAddress,
} from './cloud-api';

type FetchDirectModelAttestationsRequestParams =
  NodeFetchDirectModelAttestationsParams & {
    readonly includeSpkiFingerprint: boolean;
  };

/** Internal response shape used by Node to attach the exact request's TLS peer. */
export type DirectAttestationHttpResponse = {
  readonly response: Response;
  readonly peerSpkiFingerprint?: string;
};

/** Shared provider API transport, without Cloud-specific model routing. */
export class DirectApiClient {
  private readonly baseUrl: string;
  private readonly requestConfiguration: CloudApiRequestConfiguration;

  constructor(options: DirectAttestationClientOptions) {
    this.baseUrl = resolveCloudApiBaseUrl(
      requireDirectApiBaseUrl(options.baseUrl),
    );
    this.requestConfiguration = createCloudApiRequestConfiguration(options);
  }

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
    const request = this.createRequest(url);
    let response: Response;
    try {
      response = await this.requestApi(request);
    } catch (cause) {
      // A verified inference session can pin this transport. A rejected TLS
      // identity is a verification failure, not a retryable network outage.
      if (isVerificationError(cause)) {
        throw cause;
      }
      throw new ApiError(
        {
          code: 'api.transport_failed',
          details: { resource: 'completion_signature', reason: 'request' },
          retryable: true,
        },
        { cause },
      );
    }
    return decodeDirectCompletionSignature(
      await readCloudApiJson({ response, resource: 'completion_signature' }),
    );
  }

  protected async fetchModelAttestationsWithOptions({
    signingAlgo,
    signingAddress,
    includeSpkiFingerprint,
  }: FetchDirectModelAttestationsRequestParams): Promise<FetchedDirectModelAttestations> {
    if (signingAddress !== undefined) {
      validateApiSigningAddress({
        signingAddress,
        signingAlgo,
        field: 'signingAddress',
      });
    }
    const nonce = generateNonce();
    const url = new URL('attestation/report', this.baseUrl);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set(
      'include_tls_fingerprint',
      String(includeSpkiFingerprint),
    );
    if (signingAlgo !== undefined) {
      url.searchParams.set('signing_algo', signingAlgo);
    }
    if (signingAddress !== undefined) {
      url.searchParams.set('signing_address', signingAddress);
    }
    const request = this.createRequest(url);
    let result: DirectAttestationHttpResponse;
    try {
      result = await this.requestAttestation(request, includeSpkiFingerprint);
    } catch (cause) {
      throw new ApiError(
        {
          code: 'api.transport_failed',
          details: { resource: 'model_attestation', reason: 'request' },
          retryable: true,
        },
        { cause },
      );
    }
    const modelAttestations = decodeDirectModelAttestations(
      await readCloudApiJson({
        response: result.response,
        resource: 'model_attestation',
      }),
    );
    for (const [index, attestation] of [
      modelAttestations.servingAttestation,
      ...modelAttestations.attestations,
    ].entries()) {
      requireMatchingApiNonce({
        reportedNonce: attestation.nonce,
        requestedNonce: nonce,
        resource: 'model_attestation',
      });
      const includesSpkiFingerprint = attestation.spkiFingerprint !== undefined;
      if (includesSpkiFingerprint !== includeSpkiFingerprint) {
        const label =
          index === 0 ? 'attestation' : `all_attestations[${index - 1}]`;
        throw new ApiError({
          code: 'api.invalid_response',
          details: {
            path: `${label}.tls_cert_fingerprint`,
            expected: includeSpkiFingerprint ? 'present' : 'missing',
            actual: includesSpkiFingerprint ? 'present' : 'missing',
          },
        });
      }
    }
    return {
      ...modelAttestations,
      clientBinding: {
        nonce,
        ...(result.peerSpkiFingerprint === undefined
          ? {}
          : { spkiFingerprint: result.peerSpkiFingerprint }),
      },
    };
  }

  protected async requestAttestation(
    request: Request,
    _capturePeerSpkiFingerprint: boolean,
  ): Promise<DirectAttestationHttpResponse> {
    return { response: await fetch(request) };
  }

  /** Runtime-specific clients can override this to pin signature requests. */
  protected async requestApi(request: Request): Promise<Response> {
    return fetch(request);
  }

  private createRequest(url: URL): Request {
    const headers = mergeCloudApiRequestHeaders({
      configuration: this.requestConfiguration,
    });
    return new Request(url, { headers });
  }
}

/** Reject the Gateway default for a direct endpoint before any request setup. */
export function requireDirectApiBaseUrl(baseUrl: string | undefined): string {
  if (baseUrl !== undefined) {
    return baseUrl;
  }
  throw new ApiError({
    code: 'api.invalid_input',
    details: {
      field: 'baseUrl',
      reason: 'invalid_url',
      expected: 'an absolute HTTP(S) direct endpoint URL',
      actual: 'missing',
    },
  });
}

/**
 * Fetch direct provider evidence without requesting TLS fingerprint binding.
 *
 * @experimental Not recommended for production. Use `AttestationClient` through
 * the Gateway instead.
 */
export class DirectAttestationClient extends DirectApiClient {
  async fetchModelAttestations({
    signingAlgo,
    signingAddress,
  }: FetchDirectModelAttestationsParams = {}): Promise<FetchedDirectModelAttestations> {
    return this.fetchModelAttestationsWithOptions({
      signingAlgo,
      signingAddress,
      // TODO: Re-enable direct TLS binding once all_attestations covers every serving CVM.
      // An incomplete set can reject a later connection to another CVM's TLS key.
      // https://github.com/nearai/cloud-api/issues/1087
      includeSpkiFingerprint: false,
    });
  }
}
