import type {
  NodeNearAiSecureClientOptions,
  NodeSecureClientOptions,
  SecureChat,
} from '../types/secure-client';
import {
  createNearAiSecureChat,
  SecureClientBase,
} from '../core/secure-client';
import { AttestationClient } from './attestation-client';

/** Node verified Chat Completions transport with peer-TLS Gateway binding. */
export class NodeSecureClient extends SecureClientBase {
  constructor(options: NodeSecureClientOptions) {
    const client = new AttestationClient(options);
    const includeSpkiFingerprint =
      options.gatewayVerification?.includeSpkiFingerprint ?? true;
    super({
      options,
      evidence: {
        fetchGatewayAttestation: () =>
          client.fetchGatewayAttestation({
            signingAlgo: 'ed25519',
            includeSpkiFingerprint,
          }),
        fetchModelAttestations: (params) =>
          client.fetchModelAttestations(params),
        fetchCompletionSignature: (params) =>
          client.fetchCompletionSignature(params),
      },
    });
  }
}

/** OpenAI-compatible Node client with peer-TLS Gateway binding by default. */
export class NodeNearAiSecureClient {
  readonly chat: SecureChat;
  readonly secure: NodeSecureClient;

  constructor(options: NodeNearAiSecureClientOptions) {
    this.secure = new NodeSecureClient(options);
    this.chat = createNearAiSecureChat({ options, secure: this.secure });
  }
}
