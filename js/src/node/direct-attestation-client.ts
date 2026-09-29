import { DirectApiClient } from '../core/direct-api';
import type {
  FetchedDirectModelAttestations,
  NodeFetchDirectModelAttestationsParams,
} from '../types/direct-api';
import { type HttpsResponse, requestHttps } from './attestation-client';

/**
 * Node direct attestation client; TLS fingerprint binding is temporarily disabled.
 *
 * @experimental Not recommended for production. Use `AttestationClient` through
 * the Gateway instead.
 */
export class DirectAttestationClient extends DirectApiClient {
  async fetchModelAttestations({
    signingAlgo,
    signingAddress,
  }: NodeFetchDirectModelAttestationsParams = {}): Promise<FetchedDirectModelAttestations> {
    return this.fetchModelAttestationsWithOptions({
      signingAlgo,
      signingAddress,
      // TODO: Re-enable direct TLS binding once all_attestations covers every serving CVM.
      // An incomplete set can reject a later connection to another CVM's TLS key.
      // https://github.com/nearai/cloud-api/issues/1087
      includeSpkiFingerprint: false,
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
