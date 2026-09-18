import {
  decodeDirectAttestationReport,
  decodeDirectCompletionSignature,
} from '../boundaries/direct-api';
import type { CompletionSignature } from '../types/chat';
import type { FetchCompletionSignatureParams } from '../types/cloud-api';
import type {
  DirectAttestationClientOptions,
  FetchDirectAttestationReportParams,
  FetchedDirectAttestationReport,
  NodeFetchDirectAttestationReportParams,
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

type FetchDirectAttestationRequestParams =
  NodeFetchDirectAttestationReportParams & {
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
    this.baseUrl = resolveCloudApiBaseUrl(options.baseUrl);
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

  protected async fetchAttestationReportWithOptions({
    signingAlgo,
    signingAddress,
    includeSpkiFingerprint,
  }: FetchDirectAttestationRequestParams): Promise<FetchedDirectAttestationReport> {
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
    const report = decodeDirectAttestationReport(
      await readCloudApiJson({
        response: result.response,
        resource: 'model_attestation',
      }),
    );
    for (const [index, attestation] of [
      report.attestation,
      ...report.attestations,
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
      report,
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

/** Fetch direct provider evidence with standard Fetch (without TLS peer access). */
export class DirectAttestationClient extends DirectApiClient {
  async fetchAttestationReport({
    signingAlgo,
    signingAddress,
    includeSpkiFingerprint = false,
  }: FetchDirectAttestationReportParams = {}): Promise<FetchedDirectAttestationReport> {
    return this.fetchAttestationReportWithOptions({
      signingAlgo,
      signingAddress,
      includeSpkiFingerprint,
    });
  }
}
