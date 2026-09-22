import type { Buffer } from 'buffer';
import type {
  ChutesMeasuredDeployment,
  ChutesMeasurementBaseline,
  VerifiedChutesModelAttestation,
} from './attestation-chutes';
import type { SigningIdentity } from './attestation-common';
import type { GatewayAttestation } from './attestation-gateway';
import type {
  ModelAttestation,
  NearModelAttestation,
} from './attestation-model';
import type { CompletionSignature } from './chat';
import type { Awaitable } from './shared';

export type TcbStatus =
  | 'UpToDate'
  | 'SWHardeningNeeded'
  | 'ConfigurationNeeded'
  | 'ConfigurationAndSWHardeningNeeded'
  | 'OutOfDate'
  | 'OutOfDateConfigurationNeeded'
  | 'Revoked'
  | 'Unknown';

export type RuntimeMeasurements = {
  readonly osImageHash?: string;
  readonly composeHash?: string;
};

export type MeasuredDeployment = {
  readonly appCompose: string;
  readonly runtimeMeasurements: RuntimeMeasurements;
};

/** Facts returned by a quote verifier before SDK policy and binding checks. */
export type TdxQuoteVerificationResult = {
  tcbStatus: TcbStatus;
  advisoryIds: readonly string[];
  debugEnabled: boolean;
  reportData: Uint8Array;
  mrConfigId: Uint8Array;
  mrTd?: Uint8Array;
  rtMr0?: Uint8Array;
  rtMr1?: Uint8Array;
  rtMr2?: Uint8Array;
  rtMr3: Uint8Array;
};

export type TdxQuoteVerifier = (
  quote: string,
) => Awaitable<TdxQuoteVerificationResult>;

export type GpuEvidenceVerifier = (payload: string) => Awaitable<void>;

export type CreateTdxQuoteVerifierParams = {
  /** Collateral base URL. Defaults to Phala PCCS in browsers and Intel in Node.js. */
  readonly pccsUrl?: string;
};

export type CreateGpuEvidenceVerifierParams = {
  /** GPU attestation POST URL. Defaults to NVIDIA NRAS. */
  readonly nrasUrl?: string;
  /** Public-key GET URL. Defaults to NVIDIA's JWKS. Use only a trusted proxy. */
  readonly jwksUrl?: string;
};

export type DeploymentVerifier = (
  deployment: MeasuredDeployment,
) => Awaitable<void>;

export type AttestationPolicy = {
  readonly acceptedTcbStatuses?: readonly TcbStatus[];
};

export type ModelAttestationPolicy = AttestationPolicy & {
  readonly gpuEvidence?: 'if-present' | 'required';
  /** Accepted Chutes VM measurements. Defaults to the bundled Chutes baseline snapshot. */
  readonly chutesMeasurements?: readonly ChutesMeasurementBaseline[];
};

export type AttestationVerifiers = {
  readonly tdxQuote?: TdxQuoteVerifier;
  readonly deployment?: DeploymentVerifier;
};

export type MeasuredModelDeployment =
  | (MeasuredDeployment & { readonly provider: 'near' })
  | (ChutesMeasuredDeployment & { readonly provider: 'chutes' });

export type ModelDeploymentVerifier = (
  deployment: MeasuredModelDeployment,
) => Awaitable<void>;

export type ModelAttestationVerifiers = {
  readonly tdxQuote?: TdxQuoteVerifier;
  readonly deployment?: ModelDeploymentVerifier;
  readonly gpuEvidence?: GpuEvidenceVerifier;
};

/** Values supplied by the client for a model-attestation request. */
export type ModelClientBinding = {
  /** Fresh nonce sent in the model-attestation request. */
  readonly nonce: string;
};

export type VerifyModelAttestationParams = {
  readonly attestation: ModelAttestation;
  readonly clientBinding: ModelClientBinding;
  readonly policy?: ModelAttestationPolicy;
  readonly verifiers?: ModelAttestationVerifiers;
};

export type VerifyNearModelAttestationParams = Omit<
  VerifyModelAttestationParams,
  'attestation'
> & {
  readonly attestation: NearModelAttestation;
};

/** Values supplied or observed by the client for a Gateway attestation request. */
export type GatewayClientBinding = {
  /** Fresh nonce sent in the Gateway-attestation request. */
  readonly nonce: string;
  /** Client-observed TLS SPKI fingerprint for that request, when the runtime exposes it. */
  readonly spkiFingerprint?: string;
};

export type VerifyGatewayAttestationParams = {
  readonly attestation: GatewayAttestation;
  readonly clientBinding: GatewayClientBinding;
  /** TCB statuses accepted for this Gateway attestation. */
  readonly policy?: AttestationPolicy;
  readonly verifiers?: AttestationVerifiers;
};

/** Measurements extracted from an authenticated quote and normalized to Buffers. */
export type VerifiedTdxQuote = Omit<
  TdxQuoteVerificationResult,
  'reportData' | 'mrConfigId' | 'rtMr3' | 'mrTd' | 'rtMr0' | 'rtMr1' | 'rtMr2'
> & {
  reportData: Buffer;
  mrConfigId: Buffer;
  mrTd?: Buffer;
  rtMr0?: Buffer;
  rtMr1?: Buffer;
  rtMr2?: Buffer;
  rtMr3: Buffer;
};

/** TLS binding established by Gateway attestation verification. */
export type GatewayTlsBinding =
  | { readonly kind: 'none' }
  | {
      /** The quote-bound fingerprint matched the TLS peer observed by the client. */
      readonly kind: 'attested';
      readonly spkiFingerprint: string;
    };

export type GpuEvidenceStatus = 'not_provided' | 'verified';
export type DeploymentProvenanceStatus = 'not_checked' | 'verified';

/** Measurements and identity established by a successful attestation check. */
export type VerifiedAttestationEvidence = {
  /** Verified signer that a later response signature must match. */
  readonly signer: Readonly<SigningIdentity>;
  /** Intel TDX TCB status accepted under the applied policy. */
  readonly tcbStatus: TcbStatus;
  readonly advisoryIds: readonly string[];
  /** Deployment measurements authenticated by MRCONFIGID and RTMR3. */
  readonly deployment: MeasuredDeployment;
  /**
   * `verified` only when a caller-supplied deployment verifier ran and
   * accepted the measured deployment. A failed verifier always throws.
   */
  readonly deploymentProvenance: DeploymentProvenanceStatus;
};

/** Result returned by a successful `verifyModelAttestation` call. */
export type VerifiedNearModelAttestation = VerifiedAttestationEvidence & {
  readonly provider: 'near';
  /** A supplied NVIDIA payload was verified, or the CVM did not provide one. */
  readonly gpuEvidence: GpuEvidenceStatus;
  /** Quote-bound model public key available for the selected E2EE protocol. */
  readonly signingPublicKey?: string;
};

export type VerifiedModelAttestation =
  | VerifiedNearModelAttestation
  | VerifiedChutesModelAttestation;

/** Result returned by a successful `verifyGatewayAttestation` call. */
export type VerifiedGatewayAttestation = VerifiedAttestationEvidence & {
  /** TLS binding established from the quote layout returned by Cloud API. */
  readonly tlsBinding: GatewayTlsBinding;
};

export type VerifyModelResponseParams = {
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
  readonly signature: CompletionSignature;
  /** Model-attestation result whose signer must match `signature`. */
  readonly attestation: VerifiedNearModelAttestation;
};

export type VerifyGatewayResponseParams = {
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
  readonly signature: CompletionSignature;
  /** Gateway-attestation result whose signer must match `signature`. */
  readonly attestation: VerifiedGatewayAttestation;
};
