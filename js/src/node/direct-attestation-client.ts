import { DirectApiClient } from '../core/direct-api';
import type {
  FetchedDirectModelAttestations,
  NodeFetchDirectModelAttestationsParams,
} from '../types/direct-api';
import { type HttpsResponse, requestHttps } from './attestation-client';

/** Node client that captures the TLS peer for direct attestation requests. */
export class DirectAttestationClient extends DirectApiClient {
  async fetchModelAttestations({
    signingAlgo,
    signingAddress,
    includeSpkiFingerprint = true,
  }: NodeFetchDirectModelAttestationsParams = {}): Promise<FetchedDirectModelAttestations> {
    return this.fetchModelAttestationsWithOptions({
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
