import { InferenceClientBase } from '../core/inference-client';
import type { FetchedGatewayAttestation } from '../types/cloud-api';
import type { NodeInferenceClientOptions } from '../types/inference-client';
import { VerificationError } from '../utils/errors';
import { AttestationClient, createPinnedTlsFetch } from './attestation-client';

/** Node verified Chat Completions transport with attested-SPKI-pinned Gateway requests. */
export class NodeInferenceClient extends InferenceClientBase {
  private readonly attestationClient: AttestationClient;
  private readonly includeSpkiFingerprint: boolean;

  constructor(options: NodeInferenceClientOptions) {
    super(options);
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

  protected override createGatewayFetch(
    peerSpkiFingerprint?: string,
  ): typeof globalThis.fetch {
    let gatewayFetch = globalThis.fetch.bind(globalThis);
    if (this.includeSpkiFingerprint) {
      if (peerSpkiFingerprint === undefined) {
        throw new VerificationError({
          code: 'binding.spki_fingerprint_required',
        });
      }
      gatewayFetch = this.createPinnedTlsFetch(peerSpkiFingerprint);
    }
    return gatewayFetch;
  }

  /** Isolated for the Node transport tests; runtime code delegates to the public helper. */
  protected createPinnedTlsFetch(
    spkiFingerprint: string,
  ): typeof globalThis.fetch {
    return createPinnedTlsFetch(spkiFingerprint);
  }
}
