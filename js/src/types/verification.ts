import { GatewayAttestation } from './attestation-gateway';
import { NearModelAttestation } from './attestation-model';
import { SigningAlgo } from './attestation-common';
import {
  CompletionBytes,
  GatewaySignature,
  ProviderTeeSignature,
} from './chat';

/** Intel TDX TCB statuses returned by DCAP verification. */
export type TcbStatus =
  | 'UpToDate'
  | 'SWHardeningNeeded'
  | 'ConfigurationNeeded'
  | 'ConfigurationAndSWHardeningNeeded'
  | 'OutOfDate'
  | 'OutOfDateConfigurationNeeded'
  | 'Revoked'
  | 'Unknown';

/** Measurements extracted from an Intel-verified TDX quote. */
export type VerifiedTdxQuote = {
  tcbStatus: TcbStatus;
  advisoryIds: string[];
  debugEnabled: boolean;
  reportData: Uint8Array;
  mrConfigId: Uint8Array;
  rtMr3: Uint8Array;
};

/** Injectable boundary for Intel DCAP verification. */
export type QuoteVerifier = {
  verify(quote: string): Promise<VerifiedTdxQuote>;
};

/** Injectable boundary for NVIDIA NRAS verification. */
export type GpuVerifier = {
  /** Resolves only when the supplied GPU evidence satisfies the verifier. */
  verify(nvidiaPayload: string): Promise<void>;
};

export type VerifiedRuntimeMeasurements = {
  osImageHash?: string;
  composeHash?: string;
};

/**
 * Caller-defined deployment provenance policy. The SDK supplies the measured
 * compose bytes, image digests, and RTMR3 values, but never turns a registry
 * lookup into a provenance verdict.
 */
export type ProvenanceVerifier = {
  verify(input: {
    appCompose: string;
    imageDigests: string[];
    runtimeMeasurements: VerifiedRuntimeMeasurements;
  }): Promise<void>;
};

export type NearVerificationPolicy = {
  /** Defaults to `UpToDate` and `OutOfDate`. */
  allowedTcbStatuses?: readonly TcbStatus[];
  /** Defaults to false so CPU-only CVMs remain verifiable. */
  requireGpuEvidence?: boolean;
  /**
   * Require a caller-supplied provenance verifier before reporting a successful
   * result. Defaults to false because the SDK has no embedded allowlist for a
   * particular NEAR deployment.
   */
  requireDeploymentProvenance?: boolean;
};

type BaseVerificationInput = {
  /** A caller-generated, caller-retained 32-byte hex nonce. */
  expectedNonce: string;
  quoteVerifier?: QuoteVerifier;
  provenanceVerifier?: ProvenanceVerifier;
  policy?: NearVerificationPolicy;
};

export type VerifyNearModelAttestationInput = BaseVerificationInput & {
  attestation: NearModelAttestation;
  gpuVerifier?: GpuVerifier;
};

export type VerifyGatewayAttestationInput = BaseVerificationInput & {
  attestation: GatewayAttestation;
  /**
   * SHA-256 of the SPKI from the same TLS connection used for the report and
   * the client-visible gateway response. Browser fetch cannot provide this.
   */
  peerTlsCertFingerprint: string;
};

/** How the Intel-signed report data binds the verified signer and nonce. */
export type ReportDataBinding =
  | {
      /** Quote binds the signer and fresh nonce, with no TLS claim. */
      kind: 'signer_nonce';
    }
  | {
      /** Quote additionally binds a TLS fingerprint declared in the report. */
      kind: 'signer_declared_tls_nonce';
      tlsCertFingerprint: string;
    }
  | {
      /**
       * The quote-bound TLS fingerprint matched a fingerprint observed on the
       * same peer connection.
       */
      kind: 'signer_peer_tls_nonce';
      tlsCertFingerprint: string;
    };

export type ModelReportDataBinding = Extract<
  ReportDataBinding,
  { kind: 'signer_nonce' | 'signer_declared_tls_nonce' }
>;

export type GatewayReportDataBinding = Extract<
  ReportDataBinding,
  { kind: 'signer_peer_tls_nonce' }
>;

export type VerifiedDstackAttestation<
  TReportDataBinding extends ReportDataBinding = ReportDataBinding,
> = {
  signingAddress: string;
  signingAlgo: SigningAlgo;
  reportDataBinding: TReportDataBinding;
  tcbStatus: TcbStatus;
  advisoryIds: string[];
  appCompose: string;
  imageDigests: string[];
  runtimeMeasurements: VerifiedRuntimeMeasurements;
  /** Whether a caller-supplied deployment provenance policy was satisfied. */
  provenanceVerified: boolean;
  /** Present only when GPU evidence was supplied and successfully verified. */
  gpuVerified?: true;
};

export type VerifiedNearModelAttestation =
  VerifiedDstackAttestation<ModelReportDataBinding> & {
    kind: 'near_model';
  };

export type VerifiedGatewayAttestation =
  VerifiedDstackAttestation<GatewayReportDataBinding> & {
    kind: 'gateway';
  };

export type VerifyProviderTeeResponseInput = CompletionBytes & {
  signature: ProviderTeeSignature;
  verifiedModelAttestation: VerifiedNearModelAttestation;
};

export type VerifyGatewayResponseInput = CompletionBytes & {
  signature: GatewaySignature;
  verifiedGatewayAttestation: VerifiedGatewayAttestation;
};

export type VerifiedResponseSignature = {
  scope: 'model_tee' | 'gateway';
  signingAddress: string;
  signingAlgo: SigningAlgo;
};
