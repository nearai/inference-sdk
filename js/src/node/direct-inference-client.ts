import { DirectApiClient } from '../core/direct-api';
import {
  DirectInferenceClientBase,
  type CreateDirectSessionTransportParams,
} from '../core/direct-inference-client';
import type { InferenceSessionTransport } from '../core/inference-client';
import type { FetchedDirectAttestationReport } from '../types/direct-api';
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

/** Direct model transport with preflight verification and a verified TLS-key allowlist. */
export class NodeDirectInferenceClient extends DirectInferenceClientBase {
  private readonly attestationClient: DirectAttestationClient;
  private readonly nodeOptions: NodeDirectInferenceClientOptions;

  constructor(options: NodeDirectInferenceClientOptions) {
    super(options);
    this.nodeOptions = options;
    this.attestationClient = new DirectAttestationClient(options);
  }

  protected override fetchAttestationReport(): Promise<FetchedDirectAttestationReport> {
    return this.attestationClient.fetchAttestationReport({
      signingAlgo: this.signingAlgo,
      includeSpkiFingerprint:
        this.nodeOptions.modelVerification?.includeSpkiFingerprint ?? true,
    });
  }

  protected override createDirectSessionTransport({
    attestations,
    tlsBinding,
  }: CreateDirectSessionTransportParams): InferenceSessionTransport {
    const fingerprints = attestations.flatMap((candidate) =>
      candidate.spkiFingerprint === undefined
        ? []
        : [candidate.spkiFingerprint],
    );
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
