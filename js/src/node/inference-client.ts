import { CloudApiClient } from '../core/cloud-api';
import {
  InferenceClientBase,
  type GatewaySessionTransport,
} from '../core/inference-client';
import type { FetchedGatewayAttestation } from '../types/cloud-api';
import type { NodeInferenceClientOptions } from '../types/inference-client';
import { VerificationError } from '../utils/errors';
import { AttestationClient, createPinnedTlsFetch } from './attestation-client';

/** Catalog, model attestation, and signature requests over the Gateway session transport. */
class GatewaySessionEvidenceClient extends CloudApiClient {
  private readonly gatewayFetch: typeof globalThis.fetch;

  constructor(
    options: NodeInferenceClientOptions,
    gatewayFetch: typeof globalThis.fetch,
  ) {
    super(options);
    this.gatewayFetch = gatewayFetch;
  }

  protected override requestCloudApi(request: Request): Promise<Response> {
    return this.gatewayFetch(request);
  }
}

/** Node verified Chat Completions transport with attested-SPKI-pinned Gateway requests. */
export class NodeInferenceClient extends InferenceClientBase {
  private readonly attestationClient: AttestationClient;
  private readonly nodeOptions: NodeInferenceClientOptions;
  private readonly includeSpkiFingerprint: boolean;

  constructor(options: NodeInferenceClientOptions) {
    super(options);
    this.nodeOptions = options;
    this.attestationClient = new AttestationClient(options);
    this.includeSpkiFingerprint =
      options.gatewayVerification?.includeSpkiFingerprint ?? true;
  }

  protected override fetchGatewayAttestation(): Promise<FetchedGatewayAttestation> {
    return this.attestationClient.fetchGatewayAttestation({
      signingAlgo: this.signingAlgo,
      includeSpkiFingerprint: this.includeSpkiFingerprint,
    });
  }

  protected override createGatewaySessionTransport(
    peerSpkiFingerprint?: string,
  ): GatewaySessionTransport {
    let gatewayFetch = globalThis.fetch.bind(globalThis);
    if (this.includeSpkiFingerprint) {
      if (peerSpkiFingerprint === undefined) {
        throw new VerificationError({
          code: 'binding.spki_fingerprint_required',
        });
      }
      gatewayFetch = this.createPinnedTlsFetch(peerSpkiFingerprint);
    }
    const client = new GatewaySessionEvidenceClient(
      this.nodeOptions,
      gatewayFetch,
    );
    return {
      fetch: gatewayFetch,
      fetchModelMetadata: (model) => client.fetchModelMetadata(model),
      fetchModelAttestations: (params) => client.fetchModelAttestations(params),
      fetchCompletionSignature: (params) =>
        client.fetchCompletionSignature(params),
    };
  }

  /** Isolated for the Node transport tests; runtime code delegates to the public helper. */
  protected createPinnedTlsFetch(
    spkiFingerprint: string,
  ): typeof globalThis.fetch {
    return createPinnedTlsFetch(spkiFingerprint);
  }
}
