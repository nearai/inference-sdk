import { DirectApiClient } from '../core/direct-api';
import type {
  FetchedDirectAttestationReport,
  NodeFetchDirectAttestationReportParams,
} from '../types/direct-api';
import { type HttpsResponse, requestHttps } from './attestation-client';

/** Node client that captures the TLS peer for direct attestation requests. */
export class DirectAttestationClient extends DirectApiClient {
  async fetchAttestationReport({
    signingAlgo,
    signingAddress,
    includeSpkiFingerprint = true,
  }: NodeFetchDirectAttestationReportParams = {}): Promise<FetchedDirectAttestationReport> {
    return this.fetchAttestationReportWithOptions({
      signingAlgo,
      signingAddress,
      includeSpkiFingerprint,
    });
  }

  protected override requestAttestation(
    request: Request,
    capturePeerSpkiFingerprint: boolean,
  ): Promise<HttpsResponse> {
    if (new URL(request.url).protocol !== 'https:') {
      return super.requestAttestation(request, capturePeerSpkiFingerprint);
    }
    return requestHttps({ request, capturePeerSpkiFingerprint });
  }
}
