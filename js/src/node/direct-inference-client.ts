import { getDirectSpkiFingerprints } from '../core/attestation-direct';
import { DirectApiClient } from '../core/direct-api';
import {
  DirectInferenceClientBase,
  type CreateDirectSessionTransportParams,
} from '../core/direct-inference-client';
import type { InferenceSessionTransport } from '../core/inference-client';
import type { FetchedDirectModelAttestations } from '../types/direct-api';
import type { NodeDirectInferenceClientOptions } from '../types/direct-inference-client';
import { createPinnedTlsFetch } from './attestation-client';
import { DirectAttestationClient } from './direct-attestation-client';

class DirectSessionAttestationClient extends DirectApiClient {
  constructor(
    options: NodeDirectInferenceClientOptions,
    private readonly pinnedTlsFetch: typeof globalThis.fetch,
  ) {
    super(options);
  }

  protected override requestApi(request: Request): Promise<Response> {
    return this.pinnedTlsFetch(request);
  }
}

/**
 * Node direct model transport with preflight verification.
 *
 * @experimental Not recommended for production. Use `InferenceClient` through
 * the Gateway instead.
 */
export class NodeDirectInferenceClient extends DirectInferenceClientBase {
  private readonly attestationClient: DirectAttestationClient;
  private readonly nodeOptions: NodeDirectInferenceClientOptions;

  constructor(options: NodeDirectInferenceClientOptions) {
    super(options);
    this.nodeOptions = options;
    this.attestationClient = new DirectAttestationClient(options);
  }

  protected override fetchModelAttestations(): Promise<FetchedDirectModelAttestations> {
    return this.attestationClient.fetchModelAttestations({
      signingAlgo: this.signingAlgo,
    });
  }

  protected override createDirectSessionTransport({
    attestations,
    tlsBinding,
  }: CreateDirectSessionTransportParams): InferenceSessionTransport {
    const fingerprints = getDirectSpkiFingerprints(attestations);
    const pinnedTlsFetch =
      tlsBinding.kind === 'attested'
        ? createPinnedTlsFetch(fingerprints)
        : globalThis.fetch.bind(globalThis);
    const client = new DirectSessionAttestationClient(
      this.nodeOptions,
      pinnedTlsFetch,
    );
    return {
      fetch: pinnedTlsFetch,
      fetchCompletionSignature: (params) =>
        client.fetchCompletionSignature(params),
    };
  }
}
