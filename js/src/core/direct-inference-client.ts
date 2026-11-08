import type { FetchedDirectModelAttestations } from '../types/direct-api';
import type {
  DirectInferenceClientOptions,
  NodeDirectInferenceClientOptions,
  VerifiedDirectCompletionResult,
  DirectAttestationVerificationResult,
  VerifyDirectModelResponseParams,
} from '../types/direct-inference-client';
import type {
  DirectTlsBinding,
  VerifiedDirectModelAttestation,
} from '../types/direct-verification';
import { hexToBuffer } from '../utils/common';
import { VerificationError } from '../utils/errors';
import { verifyDirectModelAttestations } from './attestation-direct';
import { parseSignatureHex, verifyModelResponse } from './chat';
import { DirectAttestationClient, requireDirectApiBaseUrl } from './direct-api';
import {
  VerifiedInferenceClientBase,
  type InferenceSession,
  type InferenceSessionTransport,
} from './inference-client';

export type CreateDirectSessionTransportParams = {
  readonly attestations: readonly VerifiedDirectModelAttestation[];
  readonly tlsBinding: DirectTlsBinding;
};

/** Direct-endpoint preflight over the shared Chat, E2EE and response-cache implementation. */
export abstract class DirectInferenceClientBase extends VerifiedInferenceClientBase<
  VerifiedDirectCompletionResult,
  DirectAttestationVerificationResult
> {
  private readonly directOptions: NodeDirectInferenceClientOptions;

  protected constructor(options: NodeDirectInferenceClientOptions) {
    super({
      ...options,
      baseUrl: requireDirectApiBaseUrl(options.baseUrl),
    });
    this.directOptions = options;
  }

  protected abstract fetchModelAttestations(): Promise<FetchedDirectModelAttestations>;

  protected abstract createDirectSessionTransport(
    params: CreateDirectSessionTransportParams,
  ): InferenceSessionTransport;

  protected override async createVerificationState(
    model: string,
  ): Promise<
    InferenceSession<
      VerifiedDirectCompletionResult,
      DirectAttestationVerificationResult
    >
  > {
    const fetched = await this.fetchModelAttestations();
    const verifiedModelAttestations = await verifyDirectModelAttestations({
      ...fetched,
      policy: this.directOptions.modelVerification?.policy,
      verifiers: this.getModelVerifiers(model),
    });
    const servingSigner = verifiedModelAttestations.servingAttestation.signer;
    const ohttpKeyConfig = this.getOhttpKeyConfig(
      fetched.ohttpAttestation,
      servingSigner,
    );
    const requiresServingSigner =
      this.ohttpEnabled ||
      verifiedModelAttestations.tlsBinding.kind === 'attested';
    const modelAttestation = verifiedModelAttestations.attestations.find(
      (candidate) =>
        candidate.signer.signingAlgo === this.signingAlgo &&
        candidate.signingPublicKey !== undefined &&
        (!requiresServingSigner ||
          (candidate.signer.signingAlgo === servingSigner.signingAlgo &&
            hexToBuffer(candidate.signer.signingAddress).equals(
              hexToBuffer(servingSigner.signingAddress),
            ))),
    );
    if (modelAttestation?.signingPublicKey === undefined) {
      throw new VerificationError({ code: 'e2ee.model_public_key_required' });
    }
    const signingAddress = hexToBuffer(modelAttestation.signer.signingAddress);
    // Encryption, TLS pins and response verification use the same signer group.
    const attestations = verifiedModelAttestations.attestations.filter(
      (candidate) =>
        candidate.signer.signingAlgo === this.signingAlgo &&
        hexToBuffer(candidate.signer.signingAddress).equals(signingAddress),
    );
    const transport = this.createDirectSessionTransport({
      attestations,
      tlsBinding: verifiedModelAttestations.tlsBinding,
    });
    return {
      attestationResult: {
        ...verifiedModelAttestations,
        verifiedAt: Date.now(),
      },
      modelKey: {
        signingAlgo: this.signingAlgo,
        publicKey: modelAttestation.signingPublicKey,
      },
      transport: {
        ...transport,
        fetch: this.createCompletionFetch(transport.fetch, ohttpKeyConfig),
      },
      verifyResponse: ({ id, requestBody, responseBody, signature }) => {
        const matchingAttestations = verifyDirectModelResponse({
          requestBody,
          responseBody,
          signature,
          attestations,
        });
        return {
          id,
          completionId: id,
          signatureKind: 'provider_tee',
          signature,
          attestations: matchingAttestations,
        };
      },
    };
  }
}

/**
 * Browser-compatible direct model client without TLS fingerprint binding.
 *
 * @experimental
 */
export class DirectInferenceClient extends DirectInferenceClientBase {
  private readonly attestationClient: DirectAttestationClient;

  constructor(options: DirectInferenceClientOptions) {
    super(options);
    this.attestationClient = new DirectAttestationClient(options);
  }

  protected override fetchModelAttestations(): Promise<FetchedDirectModelAttestations> {
    return this.attestationClient.fetchModelAttestations({
      signingAlgo: this.signingAlgo,
    });
  }

  protected override createDirectSessionTransport(
    _params: CreateDirectSessionTransportParams,
  ): InferenceSessionTransport {
    return {
      fetch: globalThis.fetch.bind(globalThis),
      fetchCompletionSignature: (params) =>
        this.attestationClient.fetchCompletionSignature(params),
    };
  }
}

/**
 * Verify the exact completion bytes and return the verified attestations sharing
 * its signer.
 */
export function verifyDirectModelResponse({
  requestBody,
  responseBody,
  signature,
  attestations,
}: VerifyDirectModelResponseParams): readonly VerifiedDirectModelAttestation[] {
  if (signature.kind !== 'provider_tee') {
    throw new VerificationError({
      code: 'signature.kind_mismatch',
      details: { expected: 'provider_tee', actual: signature.kind },
    });
  }
  const signer = parseSignatureHex(
    signature.signer.signingAddress,
    'signer.signingAddress',
  );
  const matching = attestations.filter(
    (candidate) =>
      candidate.signer.signingAlgo === signature.signer.signingAlgo &&
      hexToBuffer(candidate.signer.signingAddress).equals(signer),
  );
  const attestation = matching[0];
  if (attestation === undefined) {
    throw new VerificationError({ code: 'signature.signer_mismatch' });
  }
  verifyModelResponse({ requestBody, responseBody, signature, attestation });
  return matching;
}
