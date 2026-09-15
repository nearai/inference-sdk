import { CloudApiClient } from '../core/cloud-api';
import {
  SecureClientBase,
  type CreateGatewaySessionTransportParams,
  type GatewaySessionTransport,
} from '../core/secure-client';
import type { FetchedGatewayAttestation } from '../types/cloud-api';
import type { NodeSecureClientOptions } from '../types/secure-client';
import { AttestationClient, createPinnedTlsFetch } from './attestation-client';

/** Model and receipt evidence client bound to one verified Gateway transport. */
class GatewaySessionEvidenceClient extends CloudApiClient {
  private readonly gatewayFetch: typeof globalThis.fetch;

  constructor(
    options: NodeSecureClientOptions,
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
export class NodeSecureClient extends SecureClientBase {
  private readonly attestationClient: AttestationClient;
  private readonly nodeOptions: NodeSecureClientOptions;
  private readonly includeSpkiFingerprint: boolean;

  constructor(options: NodeSecureClientOptions) {
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

  protected override createGatewaySessionTransport({
    tlsBinding,
  }: CreateGatewaySessionTransportParams): GatewaySessionTransport {
    const gatewayFetch =
      tlsBinding.kind === 'attested'
        ? this.createPinnedTlsFetch(tlsBinding.spkiFingerprint)
        : globalThis.fetch;
    const client = new GatewaySessionEvidenceClient(
      this.nodeOptions,
      gatewayFetch,
    );
    return {
      fetch: gatewayFetch,
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
